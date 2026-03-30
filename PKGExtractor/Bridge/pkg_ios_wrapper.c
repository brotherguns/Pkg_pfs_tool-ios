/*
 * pkg_ios_wrapper.c
 *
 * Bridges pkg_pfs_tool's C library to the iOS Swift layer.
 *
 * Key behaviour:
 *   - Reads the PKG's content_id from the header (offset 0x40)
 *   - Writes a temp config = bundled config + zero passcode for that content_id
 *   - Runs extraction with keymgr → pkg_alloc → pfs_unpack_all
 *   - error() longjmps instead of calling exit() (via util_ios.c)
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
/* Thread-local abort state (definitions for extern decls in header)   */
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
    fprintf(stderr, "pkg_ios_abort (no context): %s\n", message ? message : "?");
    abort();
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
/* PFS options callback — skip all signature/hash checks              */
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
/* Read content_id from PKG header (offset 0x40, up to 48 bytes)     */
/* Returns 1 on success, 0 on failure.                                */
/* ------------------------------------------------------------------ */

#define PKG_CONTENT_ID_OFFSET  0x40
#define PKG_CONTENT_ID_SIZE    0x30

static int read_pkg_content_id(const char* pkg_path, char* out, size_t out_size) {
    FILE* f = fopen(pkg_path, "rb");
    if (!f) return 0;
    if (fseek(f, PKG_CONTENT_ID_OFFSET, SEEK_SET) != 0) { fclose(f); return 0; }
    size_t n = fread(out, 1, PKG_CONTENT_ID_SIZE < out_size - 1
                              ? PKG_CONTENT_ID_SIZE : out_size - 1, f);
    fclose(f);
    if (n == 0) return 0;
    out[n] = '\0';
    /* Sanitise — content_id should be ASCII printable */
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)out[i] < 0x20 || (unsigned char)out[i] > 0x7E) {
            out[i] = '\0';
            break;
        }
    }
    return out[0] != '\0';
}

/* ------------------------------------------------------------------ */
/* Build a temp config = original config + zero-passcode for this ID */
/* Returns a malloc'd path to the temp file, or NULL on failure.      */
/* Caller must free() and unlink() the returned path.                 */
/* ------------------------------------------------------------------ */

static char* make_temp_config(const char* base_config_path,
                               const char* content_id,
                               const char* tmp_dir) {
    /* Read base config */
    FILE* f = fopen(base_config_path, "rb");
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

    /* Build temp file path */
    char* tmp_path = (char*)malloc(4096);
    if (!tmp_path) { free(base); return NULL; }
    snprintf(tmp_path, 4096, "%s/keymgr_tmp.ini", tmp_dir);

    /* Write base config + new section */
    FILE* out = fopen(tmp_path, "wb");
    if (!out) { free(base); free(tmp_path); return NULL; }
    fwrite(base, 1, (size_t)sz, out);
    fprintf(out,
            "\n\n; Auto-injected by PKGExtractor (all-zero passcode)\n"
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
    struct pkg*       pkg      = NULL;
    char*             tmp_cfg  = NULL;
    struct ios_cb_ctx ctx;
    int ret = -1;

    if (!pkg_path || !output_dir || !config_path) {
        set_error("NULL argument passed to pkg_ios_extract");
        return -1;
    }

    mkdir_p(output_dir);

    /* -------------------------------------------------------------- */
    /* Step 1: Read content_id from PKG header and build merged config */
    /* -------------------------------------------------------------- */
    char content_id[PKG_CONTENT_ID_SIZE + 4];
    memset(content_id, 0, sizeof(content_id));

    if (read_pkg_content_id(pkg_path, content_id, sizeof(content_id))) {
        /* Build a temp dir for the merged config (same dir as output) */
        tmp_cfg = make_temp_config(config_path, content_id, output_dir);
    }

    /* Use merged config if we built one, otherwise fall back to original */
    const char* active_config = tmp_cfg ? tmp_cfg : config_path;

    /* -------------------------------------------------------------- */
    /* Step 2: Arm longjmp so error() doesn't exit() the process      */
    /* -------------------------------------------------------------- */
    g_pkg_abort_active = 1;
    g_pkg_abort_msg[0] = '\0';

    if (setjmp(g_pkg_abort_jmp) != 0) {
        /* Jumped here from pkg_ios_abort() inside C library */
        set_error(g_pkg_abort_msg[0] ? g_pkg_abort_msg : "extraction failed");
        if (pkg) { pkg_free(pkg); pkg = NULL; }
        keymgr_finalize();
        g_pkg_abort_active = 0;
        if (tmp_cfg) { unlink(tmp_cfg); free(tmp_cfg); }
        return -1;
    }

    /* -------------------------------------------------------------- */
    /* Step 3: Extract                                                */
    /* -------------------------------------------------------------- */
    if (!keymgr_initialize(active_config)) {
        set_error("keymgr_initialize failed — check config.ini");
        goto done;
    }

    pkg = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    if (!pkg) {
        /* Build a helpful error that shows what content_id we saw */
        char errbuf[600];
        if (content_id[0])
            snprintf(errbuf, sizeof(errbuf),
                     "pkg_alloc failed — keys missing for content_id: %s\n"
                     "Add this section to config.ini:\n"
                     "[%s]\n"
                     "passcode=00000000000000000000000000000000",
                     content_id, content_id);
        else
            snprintf(errbuf, sizeof(errbuf),
                     "pkg_alloc failed — not a valid PS4 PKG file");
        set_error(errbuf);
        goto done;
    }

    if (!pkg->inner_pfs) {
        set_error("PKG has no inner PFS image (unsupported PKG type?)");
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
    if (tmp_cfg) { unlink(tmp_cfg); free(tmp_cfg); }
    return ret;
}
