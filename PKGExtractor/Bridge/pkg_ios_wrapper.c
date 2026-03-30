/*
 * pkg_ios_wrapper.c
 *
 * Bridges pkg_pfs_tool's C library to the iOS Swift layer.
 *
 * Key design decisions:
 *  - PKG_FLAGS_SIGNED_EKPFS is set on BOTH retail AND fake-signed pkgs.
 *    We do NOT use it to block extraction — let the C library try all keys.
 *  - For fpkgs created with all-zero passcode, we inject a per-content-ID
 *    passcode=000...000 entry into a temporary config so keymgr picks it up.
 *  - error() in util_ios.c calls pkg_ios_abort() which longjmps back here
 *    instead of calling exit(), so the app doesn't crash.
 */

#include "pkg_ios_wrapper.h"
#include "pkg_ios_abort.h"

#include "common.h"
#include "pkg.h"
#include "pfs.h"
#include "keymgr.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* Thread-local abort + warning-log state                              */
/* ------------------------------------------------------------------ */

_Thread_local jmp_buf  g_pkg_abort_jmp;
_Thread_local int      g_pkg_abort_active = 0;
_Thread_local char     g_pkg_abort_msg[512];
_Thread_local char     g_pkg_warn_log[4096];

void pkg_ios_abort(const char* message) {
    if (g_pkg_abort_active) {
        strncpy(g_pkg_abort_msg,
                message ? message : "unknown error",
                sizeof(g_pkg_abort_msg) - 1);
        g_pkg_abort_msg[sizeof(g_pkg_abort_msg) - 1] = '\0';
        longjmp(g_pkg_abort_jmp, 1);
    }
    fprintf(stderr, "pkg_ios_abort (no context): %s\n", message ? message : "?");
    abort();
}

void pkg_ios_log_warning(const char* message) {
    if (!message) return;
    size_t cur = strlen(g_pkg_warn_log);
    size_t rem = sizeof(g_pkg_warn_log) - cur - 1;
    if (rem < 4) return;
    if (cur > 0) { strncat(g_pkg_warn_log, "\n", rem); rem--; }
    strncat(g_pkg_warn_log, message, rem);
}

/* ------------------------------------------------------------------ */
/* Per-thread last-error string                                        */
/* ------------------------------------------------------------------ */

static pthread_key_t  s_err_key;
static pthread_once_t s_once = PTHREAD_ONCE_INIT;

static void destroy_err(void* p) { free(p); }
static void make_key(void)       { pthread_key_create(&s_err_key, destroy_err); }

static void set_error(const char* msg) {
    pthread_once(&s_once, make_key);
    char* buf = (char*)pthread_getspecific(s_err_key);
    if (!buf) {
        buf = (char*)malloc(4096);
        if (!buf) return;
        pthread_setspecific(s_err_key, buf);
    }
    strncpy(buf, msg, 4095);
    buf[4095] = '\0';
}

static void append_warn_log_to_error(void) {
    if (g_pkg_warn_log[0] == '\0') return;
    pthread_once(&s_once, make_key);
    char* buf = (char*)pthread_getspecific(s_err_key);
    if (!buf) return;
    size_t cur = strlen(buf);
    size_t rem = 4095 - cur;
    if (rem < 10) return;
    strncat(buf, "\n\nDetails:\n", rem);
    rem = 4095 - strlen(buf);
    strncat(buf, g_pkg_warn_log, rem);
}

const char* pkg_ios_last_error(void) {
    pthread_once(&s_once, make_key);
    const char* s = (const char*)pthread_getspecific(s_err_key);
    return s ? s : "unknown error";
}

/* ------------------------------------------------------------------ */
/* PFS options callback                                                */
/* ------------------------------------------------------------------ */

static int ios_set_pfs_options(void* arg, struct pkg* pkg, struct pfs_options* opts) {
    UNUSED(arg);
    UNUSED(pkg);
    opts->skip_signature_check  = 1;
    opts->skip_block_hash_check = 1;
    opts->finalized             = 1;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Progress callback shim                                             */
/* ------------------------------------------------------------------ */

struct ios_cb_ctx {
    pkg_ios_progress_cb cb;
    void*               user_ctx;
};

static enum cb_result ios_unpack_pre_cb(void* arg, const char* path,
                                         enum pfs_entry_type type, int* needed) {
    UNUSED(type);
    *needed = 1;
    struct ios_cb_ctx* ctx = (struct ios_cb_ctx*)arg;
    if (ctx && ctx->cb && path)
        ctx->cb(ctx->user_ctx, path);
    return CB_RESULT_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* mkdir -p                                                           */
/* ------------------------------------------------------------------ */

static void mkdir_p(const char* path) {
    char tmp[4096];
    char* p;
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len > 0 && tmp[len-1] == '/') tmp[len-1] = '\0';
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}

/* ------------------------------------------------------------------ */
/* Read content_id from PKG header (offset 0x40, up to 48 bytes)     */
/* ------------------------------------------------------------------ */

#define PKG_MAGIC_0  0x7f
#define PKG_MAGIC_1  0x43   /* 'C' */
#define PKG_MAGIC_2  0x4e   /* 'N' */
#define PKG_MAGIC_3  0x54   /* 'T' */
#define PKG_CONTENT_ID_OFFSET  0x40
#define PKG_CONTENT_ID_SIZE    0x30

static int read_content_id(const char* pkg_path, char* out_id, size_t out_size) {
    FILE* f = fopen(pkg_path, "rb");
    if (!f) return 0;

    uint8_t magic[4] = { 0 };
    if (fread(magic, 1, 4, f) != 4 ||
        magic[0] != PKG_MAGIC_0 || magic[1] != PKG_MAGIC_1 ||
        magic[2] != PKG_MAGIC_2 || magic[3] != PKG_MAGIC_3) {
        fclose(f);
        return 0;
    }

    if (fseek(f, PKG_CONTENT_ID_OFFSET, SEEK_SET) != 0) { fclose(f); return 0; }

    size_t to_read = (out_size - 1 < PKG_CONTENT_ID_SIZE) ? out_size - 1 : PKG_CONTENT_ID_SIZE;
    size_t n = fread(out_id, 1, to_read, f);
    fclose(f);

    out_id[n] = '\0';
    /* sanitize: truncate at first non-printable byte */
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)out_id[i] < 0x20 || (unsigned char)out_id[i] > 0x7E) {
            out_id[i] = '\0';
            break;
        }
    }
    return out_id[0] != '\0';
}

/* ------------------------------------------------------------------ */
/* Build a merged config: original config.ini + zero-passcode entry  */
/* for this PKG's content_id.                                         */
/*                                                                    */
/* Why: fpkgs (fake-signed packages) are typically created with an   */
/* all-zero passcode. keymgr_generate_keys_for_title_keyset checks   */
/* a per-title passcode entry BEFORE trying the EKPFS RSA path, so   */
/* injecting passcode=000...0 directly bypasses the RSA step and     */
/* derives the correct key from content_id + zero passcode.          */
/* ------------------------------------------------------------------ */

static char s_tmp_config_path[4096];

static const char* make_temp_config(const char* base_config_path,
                                    const char* content_id) {
    /* Write to a temp file in the same directory as base_config */
    snprintf(s_tmp_config_path, sizeof(s_tmp_config_path),
             "%s.tmp_pkg_ios", base_config_path);

    /* Read original config */
    FILE* src = fopen(base_config_path, "rb");
    if (!src) return base_config_path;   /* fallback: use original */

    fseek(src, 0, SEEK_END);
    long src_size = ftell(src);
    rewind(src);
    if (src_size <= 0) { fclose(src); return base_config_path; }

    char* buf = (char*)malloc((size_t)src_size + 1);
    if (!buf) { fclose(src); return base_config_path; }
    size_t n = fread(buf, 1, (size_t)src_size, src);
    fclose(src);
    buf[n] = '\0';

    /* Check if content_id section already exists */
    int already_present = (strstr(buf, content_id) != NULL);

    FILE* dst = fopen(s_tmp_config_path, "wb");
    if (!dst) { free(buf); return base_config_path; }

    fwrite(buf, 1, n, dst);
    free(buf);

    /* Append the zero-passcode section if not already there */
    if (!already_present && content_id[0] != '\0') {
        fprintf(dst,
                "\n[%s]\n"
                "passcode=00000000000000000000000000000000\n",
                content_id);
    }

    fclose(dst);
    return s_tmp_config_path;
}

/* ------------------------------------------------------------------ */
/* Main extraction entry point                                        */
/* ------------------------------------------------------------------ */

int pkg_ios_extract(
    const char*         pkg_path,
    const char*         output_dir,
    const char*         config_path,
    pkg_ios_progress_cb progress_cb,
    void*               cb_ctx
) {
    struct pkg*       pkg = NULL;
    struct ios_cb_ctx ctx;
    int ret = -1;

    if (!pkg_path || !output_dir || !config_path) {
        set_error("NULL argument passed to pkg_ios_extract");
        return -1;
    }

    /* Reset warning log */
    g_pkg_warn_log[0] = '\0';

    /* --- Step 1: Read content_id and build merged config --- */
    char content_id[PKG_CONTENT_ID_SIZE + 4] = { 0 };
    read_content_id(pkg_path, content_id, sizeof(content_id));

    const char* effective_config = make_temp_config(config_path, content_id);

    mkdir_p(output_dir);

    /* --- Step 2: Arm longjmp so error() doesn't exit() --- */
    g_pkg_abort_active = 1;
    g_pkg_abort_msg[0] = '\0';

    if (setjmp(g_pkg_abort_jmp) != 0) {
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf), "%s",
                 g_pkg_abort_msg[0] ? g_pkg_abort_msg : "extraction failed");
        set_error(errbuf);
        append_warn_log_to_error();
        if (pkg) { pkg_free(pkg); pkg = NULL; }
        keymgr_finalize();
        g_pkg_abort_active = 0;
        return -1;
    }

    /* --- Step 3: Load keys --- */
    if (!keymgr_initialize(effective_config)) {
        set_error("keymgr_initialize failed.\n"
                  "config.ini may be missing required global keys\n"
                  "(fake_ekpfs_key, debug_ekpfs_key, sealed_key_enc_key_*, etc.)");
        append_warn_log_to_error();
        goto done;
    }

    /* --- Step 4: Open and decrypt PKG --- */
    pkg = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    if (!pkg) {
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf),
                 "pkg_alloc failed.\n"
                 "Content ID: %s\n\n"
                 "Possible causes:\n"
                 "  1. PKG is corrupt or not a valid PS4 PKG\n"
                 "  2. The PKG's passcode is NOT all zeros\n"
                 "     (try entering the correct 32-char hex passcode)\n"
                 "  3. fake_ekpfs_key in config.ini is wrong or missing\n"
                 "  4. This is a retail PKG (needs per-title passcode from\n"
                 "     your PS4's RIF/license file)",
                 content_id[0] ? content_id : "(could not read)");
        set_error(errbuf);
        append_warn_log_to_error();
        goto done;
    }

    if (!pkg->inner_pfs) {
        set_error("PKG has no inner PFS image.\n"
                  "This PKG type may not be supported (e.g. DLC-only or patch PKG).");
        goto done;
    }

    /* --- Step 5: Extract files --- */
    memset(&ctx, 0, sizeof(ctx));
    ctx.cb       = progress_cb;
    ctx.user_ctx = cb_ctx;

    char image0[4096];
    snprintf(image0, sizeof(image0), "%s/Image0", output_dir);
    mkdir_p(image0);

    if (!pfs_unpack_all(pkg->inner_pfs, image0, ios_unpack_pre_cb, &ctx)) {
        set_error("pfs_unpack_all failed — PKG may be corrupt or key derivation failed.");
        append_warn_log_to_error();
        goto done;
    }

    ret = 0;

done:
    if (pkg) pkg_free(pkg);
    keymgr_finalize();
    g_pkg_abort_active = 0;
    return ret;
}
