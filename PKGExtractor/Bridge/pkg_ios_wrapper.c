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
 *   IMPORTANT: The CLI leaves the keyset NULL in its FIRST callback and lets
 *   pkg_alloc() handle keyset creation through its normal path (lines 1101-1114
 *   of pkg.c). The passcode is only applied in the SECOND callback. We must
 *   mirror this exact flow — setting the keyset prematurely in the first
 *   callback bypasses pkg_alloc's keyset-setup logic and can cause subtle
 *   key-derivation failures.
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

/* ------------------------------------------------------------------ */
/* DIAG() — logs to stderr AND the warning-log buffer so diagnostic   */
/* text appears in both the Xcode console and the UI error view.      */
/* ------------------------------------------------------------------ */

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
/* PFS options callback — mirrors --passcode 000...000 from main.c    */
/* ------------------------------------------------------------------ */
/*
 * pkg.c calls this callback TWICE:
 *
 *   1st call (pfs_opts.keyset == NULL):
 *     Do NOT touch keyset. Return immediately so pkg_alloc runs its
 *     normal keyset-creation path (lines 1101-1114): look up the title
 *     keyset from config.ini -> if not found, allocate one with the real
 *     content_id and attempt EKPFS decryption (fails gracefully for
 *     fpkgs). This is exactly what the CLI does.
 *
 *   2nd call (pfs_opts.keyset != NULL):
 *     Apply the zero passcode to the keyset, just like the CLI's
 *     --passcode flag does in tweak_pfs_options(). has_passcode takes
 *     priority in keymgr_generate_keys_for_title_keyset, so this
 *     overrides any EKPFS-derived image_key — matching CLI behaviour.
 */
static int s_callback_count = 0;

static int ios_set_pfs_options(void* arg, struct pkg* pkg, struct pfs_options* opts) {
    UNUSED(arg);

    s_callback_count++;

    DIAG("=== ios_set_pfs_options CALL #%d ===", s_callback_count);
    DIAG("  pkg=%p  pkg->hdr=%p", (void*)pkg, pkg ? (void*)pkg->hdr : NULL);
    DIAG("  opts->keyset=%p  finalized=%d  skip_keygen=%d",
         (void*)opts->keyset, opts->finalized, opts->skip_keygen);
    DIAG("  skip_sig=%d  skip_block_hash=%d",
         opts->skip_signature_check, opts->skip_block_hash_check);

    if (opts->content_id)
        DIAG("  opts->content_id = \"%s\"", opts->content_id);
    else
        DIAG("  opts->content_id = NULL");

    if (pkg && pkg->hdr)
        DIAG("  pkg content_id = \"%s\"  pkg->finalized = %d",
             pkg->hdr->content_id, pkg->finalized);

    if (opts->keyset) {
        DIAG("  keyset->content_id = \"%s\"", opts->keyset->content_id);
        DIAG("  flags BEFORE: passcode=%d image_key=%d enc_data=%d enc_tweak=%d sig_hmac=%d",
             opts->keyset->flags.has_passcode, opts->keyset->flags.has_image_key,
             opts->keyset->flags.has_enc_data_key, opts->keyset->flags.has_enc_tweak_key,
             opts->keyset->flags.has_sig_hmac_key);

        /* ── Second call: apply zero passcode (mirrors CLI --passcode) ── */
        memset(opts->keyset->passcode, '0', sizeof(opts->keyset->passcode));
        opts->keyset->flags.has_passcode = 1;

        DIAG("  -> Applied zero passcode (32x ASCII '0' = 0x30)");
        DIAG("  flags AFTER:  passcode=%d image_key=%d enc_data=%d enc_tweak=%d sig_hmac=%d",
             opts->keyset->flags.has_passcode, opts->keyset->flags.has_image_key,
             opts->keyset->flags.has_enc_data_key, opts->keyset->flags.has_enc_tweak_key,
             opts->keyset->flags.has_sig_hmac_key);

        /* Verify passcode bytes are really 0x30 */
        DIAG("  passcode[0..3] = 0x%02X 0x%02X 0x%02X 0x%02X (expect 0x30)",
             (unsigned char)opts->keyset->passcode[0],
             (unsigned char)opts->keyset->passcode[1],
             (unsigned char)opts->keyset->passcode[2],
             (unsigned char)opts->keyset->passcode[3]);
    } else {
        DIAG("  keyset is NULL -> leaving for pkg_alloc to create");
    }

    /* Always relax checks */
    opts->skip_signature_check  = 1;
    opts->skip_block_hash_check = 1;

    DIAG("  -> Set skip_signature_check=1  skip_block_hash_check=1");
    DIAG("=== END CALL #%d ===", s_callback_count);

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

    /* Reset warning log + callback counter.
     * DIAG() calls after this point are captured and shown in the UI. */
    g_pkg_warn_log[0] = '\0';
    s_callback_count = 0;

    DIAG("========== pkg_ios_extract BEGIN ==========");
    DIAG("pkg_path    = %s", pkg_path);
    DIAG("output_dir  = %s", output_dir);
    DIAG("config_path = %s", config_path);

    /* Log file sizes */
    {
        struct stat st;
        if (stat(pkg_path, &st) == 0)
            DIAG("PKG file size = %lld bytes (%.1f MB)",
                 (long long)st.st_size, (double)st.st_size / (1024.0 * 1024.0));
        else
            DIAG("!! PKG stat FAILED: errno=%d (%s)", errno, strerror(errno));

        if (stat(config_path, &st) == 0)
            DIAG("config.ini size = %lld bytes", (long long)st.st_size);
        else
            DIAG("!! config.ini stat FAILED: errno=%d (%s)", errno, strerror(errno));
    }

    /* Quick sanity check on PKG magic */
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
    DIAG("PKG content_id = \"%s\" (len=%zu)", content_id, strlen(content_id));

    /* Dump first 16 bytes of PKG as hex */
    {
        FILE* f = fopen(pkg_path, "rb");
        if (f) {
            uint8_t hdr[16];
            size_t n = fread(hdr, 1, 16, f);
            fclose(f);
            char hex[16*3+1]; hex[0] = '\0';
            for (size_t i = 0; i < n; i++) {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%s%02X", i ? " " : "", hdr[i]);
                strncat(hex, tmp, sizeof(hex) - strlen(hex) - 1);
            }
            DIAG("PKG header: %s", hex);
        }
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
        DIAG("!! longjmp caught — error() called from C library");
        DIAG("!! abort msg: %s", g_pkg_abort_msg);
        append_warn_log_to_error();
        if (pkg) { pkg_free(pkg); pkg = NULL; }
        keymgr_finalize();
        g_pkg_abort_active = 0;
        return -1;
    }

    /* Load global keys from config.ini */
    DIAG("Calling keymgr_initialize...");
    if (!keymgr_initialize(config_path)) {
        set_error("keymgr_initialize failed.\n"
                  "config.ini may be missing, unreadable, or lack required global keys.\n"
                  "Make sure config.ini is in the app's Documents folder.");
        DIAG("!! keymgr_initialize FAILED");
        append_warn_log_to_error();
        goto done;
    }
    DIAG("keymgr_initialize OK");

    /* Check if config.ini had a title keyset for this content_id */
    {
        struct keymgr_title_keyset* pre = keymgr_get_title_keyset(content_id);
        if (pre) {
            DIAG("config.ini HAS keyset for \"%s\"", content_id);
            DIAG("  passcode=%d image_key=%d enc_data=%d enc_tweak=%d sig_hmac=%d",
                 pre->flags.has_passcode, pre->flags.has_image_key,
                 pre->flags.has_enc_data_key, pre->flags.has_enc_tweak_key,
                 pre->flags.has_sig_hmac_key);
            if (pre->flags.has_passcode) {
                DIAG("  passcode[0..3] = 0x%02X 0x%02X 0x%02X 0x%02X",
                     (unsigned char)pre->passcode[0], (unsigned char)pre->passcode[1],
                     (unsigned char)pre->passcode[2], (unsigned char)pre->passcode[3]);
            }
        } else {
            DIAG("config.ini has NO keyset for \"%s\"", content_id);
        }
    }

    /* Open and decrypt the PKG */
    DIAG("Calling pkg_alloc()...");
    pkg = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    DIAG("pkg_alloc returned: %p  (callback called %d times)", (void*)pkg, s_callback_count);

    if (!pkg) {
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf),
                 "pkg_alloc failed for: %s\n\n"
                 "Possible causes:\n"
                 "- The zero passcode doesn't match this PKG\n"
                 "- config.ini missing fake_ekpfs_key / debug_ekpfs_key\n"
                 "- PKG file corrupt or truncated\n"
                 "- mmap() failed\n"
                 "See diagnostics below for details.",
                 content_id[0] ? content_id : "(unknown)");
        set_error(errbuf);
        append_warn_log_to_error();
        goto done;
    }

    DIAG("pkg_alloc OK: pfs=%p  inner_pfs=%p", (void*)pkg->pfs, (void*)pkg->inner_pfs);

    if (!pkg->inner_pfs) {
        set_error("PKG has no inner PFS image.\n"
                  "This may be a DLC-data-only or outer-content-only PKG.");
        append_warn_log_to_error();
        goto done;
    }

    /* Extract */
    memset(&ctx, 0, sizeof(ctx));
    ctx.cb       = progress_cb;
    ctx.user_ctx = cb_ctx;

    char image0[4096];
    snprintf(image0, sizeof(image0), "%s/Image0", output_dir);
    mkdir_p(image0);

    DIAG("Calling pfs_unpack_all -> %s", image0);
    if (!pfs_unpack_all(pkg->inner_pfs, image0, ios_unpack_pre_cb, &ctx)) {
        set_error("pfs_unpack_all failed — PKG data may be corrupt or incomplete.");
        append_warn_log_to_error();
        goto done;
    }

    DIAG("pfs_unpack_all OK — extraction complete!");
    ret = 0;

done:
    DIAG("========== pkg_ios_extract END (ret=%d) ==========", ret);
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
