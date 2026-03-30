/*
 * pkg_ios_wrapper.c
 *
 * Bridges pkg_pfs_tool's C library to the iOS Swift layer.
 * - Owns the thread-local longjmp state used by util_ios.c's error()
 * - Calls keymgr_initialize → pkg_alloc → pfs_unpack_all → pkg_free
 * - Skips all signature/hash checks (for decrypted fpkg dumps)
 * - All-zero passcode is accepted via keymgr + config.ini lookup
 */

#include "pkg_ios_wrapper.h"
#include "pkg_ios_abort.h"

/* pkg_pfs_tool public headers (from pkg_pfs_tool/src/) */
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
/* Thread-local abort state (definitions for extern declarations)      */
/* ------------------------------------------------------------------ */

_Thread_local jmp_buf  g_pkg_abort_jmp;
_Thread_local int      g_pkg_abort_active = 0;
_Thread_local char     g_pkg_abort_msg[512];

void pkg_ios_abort(const char* message) {
    if (g_pkg_abort_active) {
        strncpy(g_pkg_abort_msg,
                message ? message : "unknown error",
                sizeof(g_pkg_abort_msg) - 1);
        g_pkg_abort_msg[sizeof(g_pkg_abort_msg) - 1] = '\0';
        longjmp(g_pkg_abort_jmp, 1);
    }
    /* Outside extraction context — hard abort */
    fprintf(stderr, "pkg_ios_abort (no context): %s\n", message ? message : "?");
    abort();
}

/* ------------------------------------------------------------------ */
/* Per-thread last-error string                                         */
/* ------------------------------------------------------------------ */

static pthread_key_t  s_err_key;
static pthread_once_t s_once = PTHREAD_ONCE_INIT;

static void destroy_err(void* p) { free(p); }
static void make_key(void)       { pthread_key_create(&s_err_key, destroy_err); }

static void set_error(const char* msg) {
    pthread_once(&s_once, make_key);
    char* buf = (char*)pthread_getspecific(s_err_key);
    if (!buf) {
        buf = (char*)malloc(512);
        if (!buf) return;
        pthread_setspecific(s_err_key, buf);
    }
    strncpy(buf, msg, 511);
    buf[511] = '\0';
}

const char* pkg_ios_last_error(void) {
    pthread_once(&s_once, make_key);
    const char* s = (const char*)pthread_getspecific(s_err_key);
    return s ? s : "unknown error";
}

/* ------------------------------------------------------------------ */
/* PFS options callback — skip all signature/hash checks               */
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
/* Progress callback shim                                              */
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
/* mkdir -p                                                            */
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
/* Main extraction entry point                                         */
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

    mkdir_p(output_dir);

    /* Arm longjmp guard so error() in the C library doesn't exit() */
    g_pkg_abort_active = 1;
    g_pkg_abort_msg[0] = '\0';

    if (setjmp(g_pkg_abort_jmp) != 0) {
        /* Jumped here from pkg_ios_abort() */
        set_error(g_pkg_abort_msg[0] ? g_pkg_abort_msg : "extraction failed");
        if (pkg) { pkg_free(pkg); pkg = NULL; }
        keymgr_finalize();
        g_pkg_abort_active = 0;
        return -1;
    }

    if (!keymgr_initialize(config_path)) {
        set_error("keymgr_initialize failed — check config.ini");
        goto done;
    }

    pkg = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    if (!pkg) {
        set_error("pkg_alloc failed — invalid PKG or missing keys for this title");
        goto done;
    }

    if (!pkg->inner_pfs) {
        set_error("PKG has no inner PFS (unsupported type?)");
        goto done;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.cb       = progress_cb;
    ctx.user_ctx = cb_ctx;

    char image0[4096];
    snprintf(image0, sizeof(image0), "%s/Image0", output_dir);
    mkdir_p(image0);

    if (!pfs_unpack_all(pkg->inner_pfs, image0, ios_unpack_pre_cb, &ctx)) {
        set_error("pfs_unpack_all failed — PKG may be corrupt or keys missing");
        goto done;
    }

    ret = 0;

done:
    if (pkg) pkg_free(pkg);
    keymgr_finalize();
    g_pkg_abort_active = 0;
    return ret;
}
