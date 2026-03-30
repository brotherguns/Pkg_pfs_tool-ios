/*
 * pkg_ios_wrapper.c
 *
 * Bridges pkg_pfs_tool's C library to the iOS Swift layer.
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
/* PKG header inspection                                              */
/* ------------------------------------------------------------------ */

/* PS4 PKG magic: \x7f C N T */
static const uint8_t PKG_MAGIC[4] = { 0x7f, 0x43, 0x4e, 0x54 };

#define PKG_FLAGS_OFFSET       0x04   /* uint32_t, big-endian */
#define PKG_CONTENT_ID_OFFSET  0x40
#define PKG_CONTENT_ID_SIZE    0x30

/* Bit 25 set = EKPFS is RSA-signed with retail_ekpfs_key (private, console-derived).
   Bit 25 clear = EKPFS is encrypted with debug_ekpfs_key or fake_ekpfs_key. */
#define PKG_FLAGS_SIGNED_EKPFS (1u << 25)
#define PKG_FLAGS_FINALIZED    (1u << 31)

typedef struct {
    int    valid;           /* 0 if open/read failed */
    int    is_retail;       /* 1 if PKG_FLAGS_SIGNED_EKPFS is set */
    int    is_finalized;    /* 1 if PKG_FLAGS_FINALIZED is set */
    uint32_t flags;
    char   content_id[PKG_CONTENT_ID_SIZE + 4];
} pkg_header_info_t;

static pkg_header_info_t read_pkg_header(const char* pkg_path) {
    pkg_header_info_t info;
    memset(&info, 0, sizeof(info));

    FILE* f = fopen(pkg_path, "rb");
    if (!f) return info;

    /* Check magic */
    uint8_t magic[4] = { 0 };
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, PKG_MAGIC, 4) != 0) {
        fclose(f);
        return info;
    }

    /* Read flags (big-endian uint32 at 0x04) */
    uint8_t flags_buf[4] = { 0 };
    if (fread(flags_buf, 1, 4, f) == 4) {
        info.flags = ((uint32_t)flags_buf[0] << 24) |
                     ((uint32_t)flags_buf[1] << 16) |
                     ((uint32_t)flags_buf[2] <<  8) |
                     ((uint32_t)flags_buf[3]);
        info.is_retail    = (info.flags & PKG_FLAGS_SIGNED_EKPFS) != 0;
        info.is_finalized = (info.flags & PKG_FLAGS_FINALIZED) != 0;
    }

    /* Read content_id */
    if (fseek(f, PKG_CONTENT_ID_OFFSET, SEEK_SET) == 0) {
        size_t n = fread(info.content_id, 1, PKG_CONTENT_ID_SIZE, f);
        info.content_id[n < PKG_CONTENT_ID_SIZE ? n : PKG_CONTENT_ID_SIZE] = '\0';
        for (size_t i = 0; i < n; i++) {
            if ((unsigned char)info.content_id[i] < 0x20 ||
                (unsigned char)info.content_id[i] > 0x7E) {
                info.content_id[i] = '\0';
                break;
            }
        }
    }

    fclose(f);
    info.valid = 1;
    return info;
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

    /* --- Step 1: Read and validate PKG header --- */
    pkg_header_info_t hdr = read_pkg_header(pkg_path);

    if (!hdr.valid) {
        char errbuf[512];
        snprintf(errbuf, sizeof(errbuf),
                 "Cannot open or parse PKG file.\n"
                 "Path: %s\nErrno: %s",
                 pkg_path, strerror(errno));
        set_error(errbuf);
        return -1;
    }

    if (hdr.is_retail) {
        /*
         * PKG_FLAGS_SIGNED_EKPFS is set — this is a RETAIL PKG.
         * The EKPFS blob is RSA-encrypted with retail_ekpfs_key, which is a
         * console-specific private key NOT included in any public config.ini.
         * fake_ekpfs_key and debug_ekpfs_key cannot decrypt it.
         *
         * To extract this PKG you need the per-title PASSCODE from the
         * license/RIF file on your PS4 (requires a jailbroken PS4 to dump).
         * Add it to config.ini:
         *
         *   [%s]
         *   passcode=<32-hex-char passcode from your PS4 RIF>
         */
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf),
                 "This is a RETAIL PKG (PKG_FLAGS_SIGNED_EKPFS is set).\n"
                 "Content ID: %s\n\n"
                 "Retail PKGs use a console-specific RSA key to protect\n"
                 "the EKPFS blob. fake_ekpfs_key / debug_ekpfs_key cannot\n"
                 "decrypt it.\n\n"
                 "You need the per-title passcode from the license/RIF\n"
                 "file on your jailbroken PS4. Add it to config.ini:\n\n"
                 "  [%s]\n"
                 "  passcode=<32-hex chars from RIF>",
                 hdr.content_id[0] ? hdr.content_id : "(unknown)",
                 hdr.content_id[0] ? hdr.content_id : "CONTENT_ID_HERE");
        set_error(errbuf);
        return -1;
    }

    /* PKG is debug/fake-signed — fake_ekpfs_key or debug_ekpfs_key should work */
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
    if (!keymgr_initialize(config_path)) {
        set_error("keymgr_initialize failed.\n"
                  "config.ini may be missing required global keys.");
        append_warn_log_to_error();
        goto done;
    }

    /* --- Step 4: Open and decrypt PKG --- */
    pkg = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    if (!pkg) {
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf),
                 "pkg_alloc failed for: %s\n\n"
                 "PKG flags: 0x%08X  (fake/debug-signed, not retail)\n\n"
                 "fake_ekpfs_key / debug_ekpfs_key in config.ini could not\n"
                 "decrypt this PKG's EKPFS. This usually means the PKG was\n"
                 "signed with a different key than what's in config.ini.",
                 hdr.content_id[0] ? hdr.content_id : "(unknown)",
                 hdr.flags);
        set_error(errbuf);
        append_warn_log_to_error();
        goto done;
    }

    if (!pkg->inner_pfs) {
        set_error("PKG has no inner PFS image.\n"
                  "This PKG type may not be supported (patch or DLC-only PKG).");
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
        set_error("pfs_unpack_all failed — PKG may be corrupt.");
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
