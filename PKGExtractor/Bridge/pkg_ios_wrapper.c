/*
 * pkg_ios_wrapper.c
 *
 * Bridges pkg_pfs_tool's C library to the iOS Swift layer.
 *
 * Key behaviour:
 *   - Validates PKG magic before doing anything heavy
 *   - Reads content_id from PKG header (offset 0x40)
 *   - Auto-injects zero passcode for any title not already in config.ini
 *   - Captures all C-library warning() calls into a log buffer
 *   - On failure, shows the captured warnings so you know exactly what broke
 *   - error() longjmps instead of exit() (via util_ios.c)
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
    if (cur > 0) {
        strncat(g_pkg_warn_log, "\n", rem);
        rem--;
    }
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

/* Append the captured warning log to the current error message */
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
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

/* ------------------------------------------------------------------ */
/* Validate PKG magic and read content_id                             */
/* ------------------------------------------------------------------ */

/* PS4 PKG magic: \x7f C N T */
static const uint8_t PKG_MAGIC[4] = { 0x7f, 0x43, 0x4e, 0x54 };

#define PKG_CONTENT_ID_OFFSET  0x40
#define PKG_CONTENT_ID_SIZE    0x30

static int check_pkg_file(const char* pkg_path, char* content_id_out) {
    FILE* f = fopen(pkg_path, "rb");
    if (!f) {
        return -1;  /* can't open */
    }

    /* Check magic */
    uint8_t magic[4] = { 0 };
    if (fread(magic, 1, 4, f) != 4 ||
        memcmp(magic, PKG_MAGIC, 4) != 0) {
        fclose(f);
        return -2;  /* not a PKG */
    }

    /* Read content_id */
    if (content_id_out) {
        if (fseek(f, PKG_CONTENT_ID_OFFSET, SEEK_SET) == 0) {
            size_t n = fread(content_id_out, 1, PKG_CONTENT_ID_SIZE, f);
            content_id_out[n < PKG_CONTENT_ID_SIZE ? n : PKG_CONTENT_ID_SIZE] = '\0';
            /* Strip non-printable bytes (null padding) */
            for (size_t i = 0; i < n; i++) {
                if ((unsigned char)content_id_out[i] < 0x20 ||
                    (unsigned char)content_id_out[i] > 0x7E) {
                    content_id_out[i] = '\0';
                    break;
                }
            }
        } else {
            content_id_out[0] = '\0';
        }
    }

    fclose(f);
    return 0;  /* OK */
}

/* ------------------------------------------------------------------ */
/* Build temp config = original + zero passcode for this content_id   */
/* ------------------------------------------------------------------ */

static char* make_temp_config(const char* base_path,
                               const char* content_id,
                               const char* tmp_dir) {
    FILE* f = fopen(base_path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }

    char* base = (char*)malloc((size_t)sz + 1);
    if (!base) { fclose(f); return NULL; }
    fread(base, 1, (size_t)sz, f);
    fclose(f);
    base[sz] = '\0';

    char* tmp_path = (char*)malloc(4096);
    if (!tmp_path) { free(base); return NULL; }
    snprintf(tmp_path, 4096, "%s/keymgr_tmp.ini", tmp_dir);

    FILE* out = fopen(tmp_path, "wb");
    if (!out) { free(base); free(tmp_path); return NULL; }
    fwrite(base, 1, (size_t)sz, out);
    /* Inject zero passcode for this title */
    fprintf(out,
            "\n\n; Auto-injected (zero passcode)\n"
            "[%s]\n"
            "passcode=00000000000000000000000000000000\n",
            content_id);
    fclose(out);
    free(base);
    return tmp_path;
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
    struct pkg*       pkg     = NULL;
    char*             tmp_cfg = NULL;
    struct ios_cb_ctx ctx;
    int ret = -1;

    if (!pkg_path || !output_dir || !config_path) {
        set_error("NULL argument passed to pkg_ios_extract");
        return -1;
    }

    /* Reset warning log */
    g_pkg_warn_log[0] = '\0';

    /* --- Step 1: Validate PKG file --- */
    char content_id[PKG_CONTENT_ID_SIZE + 4];
    memset(content_id, 0, sizeof(content_id));

    int magic_result = check_pkg_file(pkg_path, content_id);
    if (magic_result == -1) {
        char errbuf[512];
        snprintf(errbuf, sizeof(errbuf),
                 "Cannot open PKG file.\nPath: %s\nErrno: %s",
                 pkg_path, strerror(errno));
        set_error(errbuf);
        return -1;
    }
    if (magic_result == -2) {
        set_error("Not a valid PS4 PKG file (wrong magic bytes).\n"
                  "Make sure you copied the full, unmodified .pkg file.");
        return -1;
    }

    mkdir_p(output_dir);

    /* --- Step 2: Build merged config with zero passcode injected --- */
    if (content_id[0] != '\0') {
        tmp_cfg = make_temp_config(config_path, content_id, output_dir);
    }
    const char* active_config = tmp_cfg ? tmp_cfg : config_path;

    /* --- Step 3: Arm longjmp so error() doesn't exit() --- */
    g_pkg_abort_active = 1;
    g_pkg_abort_msg[0] = '\0';

    if (setjmp(g_pkg_abort_jmp) != 0) {
        /* Jumped here from error() inside C library */
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf), "%s",
                 g_pkg_abort_msg[0] ? g_pkg_abort_msg : "extraction failed");
        set_error(errbuf);
        append_warn_log_to_error();
        if (pkg) { pkg_free(pkg); pkg = NULL; }
        keymgr_finalize();
        g_pkg_abort_active = 0;
        if (tmp_cfg) { unlink(tmp_cfg); free(tmp_cfg); }
        return -1;
    }

    /* --- Step 4: Load keys --- */
    if (!keymgr_initialize(active_config)) {
        set_error("keymgr_initialize failed.\n"
                  "The config.ini may be missing required global keys.");
        append_warn_log_to_error();
        goto done;
    }

    /* --- Step 5: Open and decrypt PKG --- */
    pkg = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    if (!pkg) {
        char errbuf[2048];
        if (content_id[0]) {
            snprintf(errbuf, sizeof(errbuf),
                     "pkg_alloc failed for: %s\n\n"
                     "This usually means the global PS4 keys in config.ini\n"
                     "are wrong or missing (fake_ekpfs_key, debug_ekpfs_key).\n"
                     "The passcode is set to all-zeros automatically.",
                     content_id);
        } else {
            snprintf(errbuf, sizeof(errbuf),
                     "pkg_alloc failed — could not read PKG content ID");
        }
        set_error(errbuf);
        append_warn_log_to_error();
        goto done;
    }

    if (!pkg->inner_pfs) {
        set_error("PKG has no inner PFS image.\n"
                  "This PKG type is not supported (may be a patch or DLC-only PKG).");
        goto done;
    }

    /* --- Step 6: Extract files --- */
    memset(&ctx, 0, sizeof(ctx));
    ctx.cb       = progress_cb;
    ctx.user_ctx = cb_ctx;

    char image0[4096];
    snprintf(image0, sizeof(image0), "%s/Image0", output_dir);
    mkdir_p(image0);

    if (!pfs_unpack_all(pkg->inner_pfs, image0, ios_unpack_pre_cb, &ctx)) {
        set_error("pfs_unpack_all failed — PKG may be corrupt.");
        append_warn_log_to_error();
        goto done;
    }

    ret = 0;

done:
    if (pkg) pkg_free(pkg);
    keymgr_finalize();
    g_pkg_abort_active = 0;
    if (tmp_cfg) { unlink(tmp_cfg); free(tmp_cfg); }
    return ret;
}
