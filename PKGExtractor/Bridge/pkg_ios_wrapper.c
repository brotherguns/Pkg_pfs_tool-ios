/*
 * pkg_ios_wrapper.c
 *
 * Bridges pkg_pfs_tool's C library to the iOS Swift layer.
 *
 * Root cause of previous failures:
 *   The original command that works is:
 *     ./pkg_pfs_tool --passcode 00000000000000000000000000000000 -u <pkg> <out>
 *
 *   The --passcode flag causes main.c to set opts->keyset->has_passcode=1 with
 *   a zero passcode. This makes keymgr derive the image_key via:
 *     HMAC-SHA256(content_id + passcode)
 *   instead of RSA-decrypting the EKPFS blob (which requires retail_ekpfs_key
 *   or fake_ekpfs_key to be correct for that specific PKG signing).
 *
 *   Our wrapper was NOT setting opts->keyset at all, so pkg.c fell through to
 *   setup_keyset_by_image_key() which tried EKPFS decryption → wrong image_key
 *   → hash mismatch.
 *
 *   pkg.c calls our callback TWICE. On the first call opts->keyset is NULL.
 *   We must set it with the zero passcode then, so pkg.c skips EKPFS decryption.
 *   On the second call opts->keyset is already set, so we leave it alone.
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
        buf = (char*)malloc(2048);
        if (!buf) return;
        pthread_setspecific(s_err_key, buf);
    }
    strncpy(buf, msg, 2047);
    buf[2047] = '\0';
}

static void append_warn_log_to_error(void) {
    if (g_pkg_warn_log[0] == '\0') return;
    pthread_once(&s_once, make_key);
    char* buf = (char*)pthread_getspecific(s_err_key);
    if (!buf) return;
    size_t cur = strlen(buf);
    size_t rem = 2047 - cur;
    if (rem < 10) return;
    strncat(buf, "\n\nDetails:\n", rem);
    rem = 2047 - strlen(buf);
    strncat(buf, g_pkg_warn_log, rem);
}

const char* pkg_ios_last_error(void) {
    pthread_once(&s_once, make_key);
    const char* s = (const char*)pthread_getspecific(s_err_key);
    return s ? s : "unknown error";
}

/* ------------------------------------------------------------------ */
/* PFS options callback — mirrors --passcode 000...000 from main.c    */
/* ------------------------------------------------------------------ */
/*
 * pkg.c calls this callback TWICE:
 *   1st call: opts->keyset is NULL. We allocate a scratch keyset and set
 *             the zero passcode. pkg.c then sees keyset != NULL and skips
 *             setup_keyset_by_image_key() (which would try EKPFS decryption).
 *   2nd call: opts->keyset is already set. We leave it alone.
 *
 * We also always set the skip flags so signature/hash checks are bypassed.
 */
static int ios_set_pfs_options(void* arg, struct pkg* pkg, struct pfs_options* opts) {
    UNUSED(arg);
    UNUSED(pkg);

    /*
     * Inject the zero passcode on the first call (when keyset is still NULL).
     * This replicates exactly what main.c does with --passcode 00000000...
     *
     * keymgr_alloc_title_keyset(KEYMGR_FAKE_CONTENT_ID, 0):
     *   - Allocates a scratch keyset (not added to the hash table, won't be
     *     freed by keymgr_finalize — acceptable small leak per extraction).
     *   - KEYMGR_FAKE_CONTENT_ID is a placeholder; the actual content_id for
     *     HMAC key derivation comes from opts->content_id which pkg.c sets
     *     to pkg->hdr->content_id before our callback fires.
     */
    if (!opts->keyset) {
        opts->keyset = keymgr_alloc_title_keyset(KEYMGR_FAKE_CONTENT_ID, 0);
        if (opts->keyset) {
            /* passcode = all zeros, 32 bytes (KEYMGR_PASSCODE_SIZE) */
            memset(opts->keyset->passcode, 0, sizeof(opts->keyset->passcode));
            opts->keyset->flags.has_passcode = 1;
        }
    }

    /* Always skip signature and block-hash checks */
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
/* Quick PKG header peek (magic + content_id only)                   */
/* ------------------------------------------------------------------ */

static const uint8_t PKG_MAGIC[4] = { 0x7f, 0x43, 0x4e, 0x54 };
#define PKG_CONTENT_ID_OFFSET  0x40
#define PKG_CONTENT_ID_MAX     0x30

static int read_pkg_content_id(const char* pkg_path, char out_id[PKG_CONTENT_ID_MAX + 1]) {
    FILE* f = fopen(pkg_path, "rb");
    if (!f) return 0;

    uint8_t magic[4] = { 0 };
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, PKG_MAGIC, 4) != 0) {
        fclose(f); return 0;
    }
    if (fseek(f, PKG_CONTENT_ID_OFFSET, SEEK_SET) != 0) {
        fclose(f); return 0;
    }
    size_t n = fread(out_id, 1, PKG_CONTENT_ID_MAX, f);
    fclose(f);

    out_id[n < PKG_CONTENT_ID_MAX ? n : PKG_CONTENT_ID_MAX] = '\0';
    /* Clamp to printable ASCII */
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)out_id[i] < 0x20 || (unsigned char)out_id[i] > 0x7E) {
            out_id[i] = '\0'; break;
        }
    }
    return 1;
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

    /* Quick sanity check on PKG magic */
    char content_id[PKG_CONTENT_ID_MAX + 1] = { 0 };
    if (!read_pkg_content_id(pkg_path, content_id)) {
        char errbuf[512];
        snprintf(errbuf, sizeof(errbuf),
                 "Cannot open PKG or invalid magic.\nPath: %s\nErrno: %s",
                 pkg_path, strerror(errno));
        set_error(errbuf);
        return -1;
    }

    mkdir_p(output_dir);

    /* Arm longjmp so error() in the C library doesn't exit() the app */
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

    /* Load global keys from config.ini */
    if (!keymgr_initialize(config_path)) {
        set_error("keymgr_initialize failed.\n"
                  "config.ini may be missing, unreadable, or lack required global keys.\n"
                  "Make sure config.ini is in the app's Documents folder.");
        append_warn_log_to_error();
        goto done;
    }

    /*
     * Open and decrypt the PKG.
     *
     * ios_set_pfs_options (our callback) will inject a zero passcode into the
     * pfs_options keyset on the first callback invocation, causing pkg.c to use
     * HMAC key derivation (content_id + zero_passcode) instead of EKPFS blob
     * decryption. This matches:
     *   ./pkg_pfs_tool --passcode 00000000000000000000000000000000 -u <pkg> <out>
     */
    pkg = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    if (!pkg) {
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf),
                 "pkg_alloc failed for: %s\n\n"
                 "Possible causes:\n"
                 "• The zero passcode doesn't match this PKG — the image_key\n"
                 "  derived from HMAC(content_id + 0x00...00) is wrong.\n"
                 "• config.ini is missing fake_ekpfs_key / debug_ekpfs_key\n"
                 "  (needed for outer PFS signature verification).\n"
                 "• The PKG file is corrupt or truncated.",
                 content_id[0] ? content_id : "(unknown content_id)");
        set_error(errbuf);
        append_warn_log_to_error();
        goto done;
    }

    if (!pkg->inner_pfs) {
        set_error("PKG has no inner PFS image.\n"
                  "This may be a DLC-data-only or outer-content-only PKG.\n"
                  "Try extracting a different PKG.");
        goto done;
    }

    /* Extract all files to <output_dir>/Image0/ */
    memset(&ctx, 0, sizeof(ctx));
    ctx.cb       = progress_cb;
    ctx.user_ctx = cb_ctx;

    char image0[4096];
    snprintf(image0, sizeof(image0), "%s/Image0", output_dir);
    mkdir_p(image0);

    if (!pfs_unpack_all(pkg->inner_pfs, image0, ios_unpack_pre_cb, &ctx)) {
        set_error("pfs_unpack_all failed — PKG data may be corrupt or incomplete.");
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

/* ------------------------------------------------------------------ */
/* Read content_id without full extraction (for UI display)           */
/* ------------------------------------------------------------------ */

int pkg_ios_read_content_id(const char* pkg_path, char* out_buf, int buf_size) {
    if (!pkg_path || !out_buf || buf_size <= 0) return 0;
    char tmp[PKG_CONTENT_ID_MAX + 1] = { 0 };
    if (!read_pkg_content_id(pkg_path, tmp)) return 0;
    strncpy(out_buf, tmp, (size_t)(buf_size - 1));
    out_buf[buf_size - 1] = '\0';
    return 1;
}
