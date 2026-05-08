/*
 * pkg_ios_wrapper.c
 *
 * Bridges pkg_pfs_tool's C library to the iOS Swift layer.
 * Adds:
 *   - pkg_ios_list_files()        : enumerate PKG contents without writing
 *   - pkg_ios_extract_filtered()  : extract only a caller-supplied list of paths
 */

#include "pkg_ios_wrapper.h"
#include "pkg_ios_abort.h"

#include "common.h"
#include "pkg.h"
#include "pfs.h"
#include "keymgr.h"
#include "crypto.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
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
_Thread_local char     g_pkg_warn_log[16384];

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

static void _diag(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void _diag(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fprintf(stderr, "%s\n", buf);
    pkg_ios_log_warning(buf);
}
#define DIAG(...) _diag(__VA_ARGS__)

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
        buf = (char*)malloc(8192);
        if (!buf) return;
        pthread_setspecific(s_err_key, buf);
    }
    strncpy(buf, msg, 8191);
    buf[8191] = '\0';
}

static void append_warn_log_to_error(void) {
    if (g_pkg_warn_log[0] == '\0') return;
    pthread_once(&s_once, make_key);
    char* buf = (char*)pthread_getspecific(s_err_key);
    if (!buf) return;
    size_t cur = strlen(buf);
    size_t rem = 8191 - cur;
    if (rem < 10) return;
    strncat(buf, "\n\nDiagnostics:\n", rem);
    rem = 8191 - strlen(buf);
    strncat(buf, g_pkg_warn_log, rem);
}

const char* pkg_ios_last_error(void) {
    pthread_once(&s_once, make_key);
    const char* s = (const char*)pthread_getspecific(s_err_key);
    return s ? s : "unknown error";
}

/* ------------------------------------------------------------------ */
/* PFS options callback (mirrors --passcode 000...000 from main.c)    */
/* ------------------------------------------------------------------ */

static int s_callback_count = 0;

static int ios_set_pfs_options(void* arg, struct pkg* pkg, struct pfs_options* opts) {
    UNUSED(arg);
    s_callback_count++;

    DIAG("=== ios_set_pfs_options CALL #%d ===", s_callback_count);
    DIAG("  pkg=%p  opts->keyset=%p", (void*)pkg, (void*)opts->keyset);

    if (opts->keyset) {
        memset(opts->keyset->passcode, '0', sizeof(opts->keyset->passcode));
        opts->keyset->flags.has_passcode = 1;
        DIAG("  -> Applied zero passcode");
    } else {
        DIAG("  keyset is NULL -> leaving for pkg_alloc to create");
    }

    opts->skip_signature_check  = 1;
    opts->skip_block_hash_check = 1;
    return 1;
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
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}

/* ------------------------------------------------------------------ */
/* Quick PKG header peek (magic + content_id only)                    */
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
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)out_id[i] < 0x20 || (unsigned char)out_id[i] > 0x7E) {
            out_id[i] = '\0'; break;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Shared PKG open / teardown helper                                  */
/* ------------------------------------------------------------------ */

/*
 * Opens and initialises a PKG for enumeration or extraction.
 * On success, *pkg_out points to the allocated pkg.
 * On failure, returns -1 and sets the last-error string.
 * The caller must call pkg_free() + keymgr_finalize() + crypto_finalize()
 * when done.
 */
static int pkg_open(const char* pkg_path, const char* config_path,
                    struct pkg** pkg_out) {
    char content_id[PKG_CONTENT_ID_MAX + 1] = { 0 };
    if (!read_pkg_content_id(pkg_path, content_id)) {
        char errbuf[512];
        snprintf(errbuf, sizeof(errbuf),
                 "Cannot open PKG or invalid magic.\nPath: %s\nErrno: %s",
                 pkg_path, strerror(errno));
        set_error(errbuf);
        append_warn_log_to_error();
        return -1;
    }
    DIAG("PKG content_id = \"%s\"", content_id);

    if (!crypto_initialize()) {
        set_error("crypto_initialize failed.");
        append_warn_log_to_error();
        return -1;
    }
    if (!keymgr_initialize(config_path)) {
        set_error("keymgr_initialize failed.");
        append_warn_log_to_error();
        crypto_finalize();
        return -1;
    }

    *pkg_out = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    if (!*pkg_out) {
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf),
                 "pkg_alloc failed for: %s\n"
                 "Possible causes: wrong passcode, missing keys, corrupt PKG.",
                 content_id[0] ? content_id : "(unknown)");
        set_error(errbuf);
        append_warn_log_to_error();
        keymgr_finalize();
        crypto_finalize();
        return -1;
    }

    if (!(*pkg_out)->inner_pfs) {
        set_error("PKG has no inner PFS image.\n"
                  "This may be a DLC-data-only or outer-content-only PKG.");
        append_warn_log_to_error();
        pkg_free(*pkg_out);
        *pkg_out = NULL;
        keymgr_finalize();
        crypto_finalize();
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Progress / filter callback context                                 */
/* ------------------------------------------------------------------ */

struct ios_extract_ctx {
    pkg_ios_progress_cb  progress_cb;
    void*                user_ctx;
    /* filter — NULL means "extract all" */
    const char* const*   filter_paths;
    int                  filter_count;
};

/* Used for extraction: honours filter and calls progress. */
static enum cb_result ios_unpack_pre_cb(void* arg, const char* path,
                                        enum pfs_entry_type type, int* needed) {
    struct ios_extract_ctx* ctx = (struct ios_extract_ctx*)arg;

    if (ctx && ctx->filter_paths && ctx->filter_count > 0) {
        if (type == PFS_ENTRY_DIRECTORY) {
            /*
             * Always recurse into directories when a filter is active.
             * pfs_unpack_cb skips recursion entirely when *needed == 0, so
             * setting it to 0 here would hide every file inside — even ones
             * that match the filter.  We must descend the whole tree and let
             * the file-level check below decide what actually gets written.
             */
            *needed = 1;
            return CB_RESULT_CONTINUE;
        }

        /* For regular files: only extract if the path is in the filter. */
        int allowed = 0;
        for (int i = 0; i < ctx->filter_count; i++) {
            if (ctx->filter_paths[i] && strcmp(ctx->filter_paths[i], path) == 0) {
                allowed = 1;
                break;
            }
        }
        *needed = allowed;
    } else {
        *needed = 1;   /* no filter — extract everything */
    }

    /* Report progress to Swift for files being extracted. */
    if (*needed && type != PFS_ENTRY_DIRECTORY && ctx && ctx->progress_cb && path)
        ctx->progress_cb(ctx->user_ctx, path);

    return CB_RESULT_CONTINUE;
}

/* Used for listing only: never write files, but DO recurse into directories. */
static enum cb_result ios_list_pre_cb(void* arg, const char* path,
                                      enum pfs_entry_type type, int* needed) {
    /*
     * For DIRECTORY entries, needed=1 tells pfs_unpack_cb to call
     * pfs_parse_dir_entries() and descend into the folder.
     * For FILE entries, needed=0 skips the actual disk write.
     * Without this distinction, *needed=0 on every directory causes
     * pfs_unpack_cb to `goto done` before recursing, so only the
     * root-level entries are ever reported.
     */
    *needed = (type == PFS_ENTRY_DIRECTORY) ? 1 : 0;
    struct ios_extract_ctx* ctx = (struct ios_extract_ctx*)arg;
    if (ctx && ctx->progress_cb && path)
        ctx->progress_cb(ctx->user_ctx, path);
    return CB_RESULT_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* Internal core that does the actual work                             */
/* ------------------------------------------------------------------ */

static int pkg_ios_run(
    const char*          pkg_path,
    const char*          output_dir,      /* NULL for list-only */
    const char*          config_path,
    const char* const*   filter_paths,
    int                  filter_count,
    pkg_ios_progress_cb  progress_cb,
    void*                cb_ctx,
    int                  list_only
) {
    struct pkg* pkg = NULL;
    int ret = -1;

    if (!pkg_path || !config_path || (!list_only && !output_dir)) {
        set_error("NULL argument passed to pkg_ios_run");
        return -1;
    }

    g_pkg_warn_log[0] = '\0';
    s_callback_count  = 0;

    DIAG("========== pkg_ios_run BEGIN (list_only=%d) ==========", list_only);

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
        crypto_finalize();
        g_pkg_abort_active = 0;
        return -1;
    }

    if (pkg_open(pkg_path, config_path, &pkg) != 0) {
        g_pkg_abort_active = 0;
        return -1;
    }

    struct ios_extract_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.progress_cb  = progress_cb;
    ctx.user_ctx     = cb_ctx;
    ctx.filter_paths = filter_paths;
    ctx.filter_count = filter_count;

    if (list_only) {
        /* Enumerate without writing — pass a temp dir that we never actually use */
        char tmp_dir[] = "/tmp/pkg_ios_list_XXXXXX";
        char* td = mkdtemp(tmp_dir);
        const char* enum_dir = td ? td : "/tmp";

        char image0[4096];
        snprintf(image0, sizeof(image0), "%s/Image0", enum_dir);
        /* mkdir will silently fail or succeed — we don't care */
        mkdir_p(image0);

        int ok = pfs_unpack_all(pkg->inner_pfs, image0, ios_list_pre_cb, &ctx);
        if (!ok) {
            set_error("pfs_unpack_all failed during file listing.");
            append_warn_log_to_error();
        } else {
            ret = 0;
        }

        /* Clean up temp dir (best-effort) */
        if (td) {
            rmdir(image0);
            rmdir(td);
        }
    } else {
        char image0[4096];
        snprintf(image0, sizeof(image0), "%s/Image0", output_dir);
        mkdir_p(output_dir);
        mkdir_p(image0);

        DIAG("pfs_unpack_all -> %s", image0);
        if (!pfs_unpack_all(pkg->inner_pfs, image0, ios_unpack_pre_cb, &ctx)) {
            set_error("pfs_unpack_all failed — PKG data may be corrupt or incomplete.");
            append_warn_log_to_error();
        } else {
            DIAG("pfs_unpack_all OK");
            ret = 0;
        }
    }

    DIAG("========== pkg_ios_run END (ret=%d) ==========", ret);
    pkg_free(pkg);
    keymgr_finalize();
    crypto_finalize();
    g_pkg_abort_active = 0;
    return ret;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int pkg_ios_extract(
    const char*          pkg_path,
    const char*          output_dir,
    const char*          config_path,
    pkg_ios_progress_cb  progress_cb,
    void*                cb_ctx
) {
    return pkg_ios_run(pkg_path, output_dir, config_path,
                       NULL, 0, progress_cb, cb_ctx, 0);
}

int pkg_ios_extract_filtered(
    const char*          pkg_path,
    const char*          output_dir,
    const char*          config_path,
    const char* const*   filter_paths,
    int                  filter_count,
    pkg_ios_progress_cb  progress_cb,
    void*                cb_ctx
) {
    return pkg_ios_run(pkg_path, output_dir, config_path,
                       filter_paths, filter_count, progress_cb, cb_ctx, 0);
}

int pkg_ios_list_files(
    const char*          pkg_path,
    const char*          config_path,
    pkg_ios_progress_cb  list_cb,
    void*                cb_ctx
) {
    return pkg_ios_run(pkg_path, NULL, config_path,
                       NULL, 0, list_cb, cb_ctx, 1);
}

/* ------------------------------------------------------------------ */
/* pkg_ios_list_files_ex — pfs_enum_user_root_directory with sizes    */
/* ------------------------------------------------------------------ */

struct ios_list_ex_ctx {
    pkg_ios_list_cb  list_cb;
    void*            user_ctx;
};

static enum cb_result ios_list_ex_enum_cb(
    void* arg,
    struct pfs* pfs,
    pfs_ino ino,
    enum pfs_entry_type type,
    const char* path,
    uint64_t size,
    uint32_t flags
) {
    struct ios_list_ex_ctx* ctx = (struct ios_list_ex_ctx*)arg;
    UNUSED(pfs); UNUSED(ino); UNUSED(flags);
    if (ctx && ctx->list_cb && path)
        ctx->list_cb(ctx->user_ctx, path, size, type == PFS_ENTRY_DIRECTORY ? 1 : 0);
    return CB_RESULT_CONTINUE;
}

int pkg_ios_list_files_ex(
    const char*       pkg_path,
    const char*       config_path,
    pkg_ios_list_cb   list_cb,
    void*             cb_ctx
) {
    struct pkg* pkg = NULL;
    int ret = -1;

    if (!pkg_path || !config_path) {
        set_error("NULL argument passed to pkg_ios_list_files_ex");
        return -1;
    }

    g_pkg_warn_log[0] = '\0';
    s_callback_count  = 0;

    g_pkg_abort_active = 1;
    g_pkg_abort_msg[0] = '\0';

    if (setjmp(g_pkg_abort_jmp) != 0) {
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf), "%s",
                 g_pkg_abort_msg[0] ? g_pkg_abort_msg : "list_ex failed");
        set_error(errbuf);
        append_warn_log_to_error();
        if (pkg) { pkg_free(pkg); pkg = NULL; }
        keymgr_finalize();
        crypto_finalize();
        g_pkg_abort_active = 0;
        return -1;
    }

    if (pkg_open(pkg_path, config_path, &pkg) != 0) {
        g_pkg_abort_active = 0;
        return -1;
    }

    struct ios_list_ex_ctx ctx;
    ctx.list_cb  = list_cb;
    ctx.user_ctx = cb_ctx;

    if (!pfs_enum_user_root_directory(pkg->inner_pfs, ios_list_ex_enum_cb, &ctx)) {
        set_error("pfs_enum_user_root_directory failed.");
        append_warn_log_to_error();
    } else {
        ret = 0;
    }

    pkg_free(pkg);
    keymgr_finalize();
    crypto_finalize();
    g_pkg_abort_active = 0;
    return ret;
}

/* ------------------------------------------------------------------ */
/* Read content_id without full decryption (for UI display)           */
/* ------------------------------------------------------------------ */

int pkg_ios_read_content_id(const char* pkg_path, char* out_buf, int buf_size) {
    if (!pkg_path || !out_buf || buf_size <= 0) return 0;
    char tmp[PKG_CONTENT_ID_MAX + 1] = { 0 };
    if (!read_pkg_content_id(pkg_path, tmp)) return 0;
    strncpy(out_buf, tmp, (size_t)(buf_size - 1));
    out_buf[buf_size - 1] = '\0';
    return 1;
}
