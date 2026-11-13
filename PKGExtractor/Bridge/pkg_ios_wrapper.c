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
#include <strings.h>
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
/* User-supplied credentials (passcode / EKC)                          */
/* ------------------------------------------------------------------ */

static char    s_user_passcode[KEYMGR_PASSCODE_SIZE];
static int     s_has_user_passcode = 0;
static uint8_t s_user_ekc[KEYMGR_CONTENT_KEY_SIZE + KEYMGR_SELF_KEY_SIZE];
static int     s_has_user_ekc = 0;

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int pkg_ios_set_credentials(const char* passcode, const char* ekc_hex) {
    s_has_user_passcode = 0;
    s_has_user_ekc      = 0;

    if (passcode && passcode[0]) {
        if (strlen(passcode) != KEYMGR_PASSCODE_SIZE) {
            set_error("Passcode must be exactly 32 characters.");
            return -1;
        }
        memcpy(s_user_passcode, passcode, sizeof(s_user_passcode));
        s_has_user_passcode = 1;
    }

    if (ekc_hex && ekc_hex[0]) {
        if (strlen(ekc_hex) != sizeof(s_user_ekc) * 2) {
            set_error("EKC must be 64 hex characters (content key seed + SELF key seed).");
            s_has_user_passcode = 0;
            return -1;
        }
        for (size_t i = 0; i < sizeof(s_user_ekc); i++) {
            int hi = hex_nibble(ekc_hex[i * 2]);
            int lo = hex_nibble(ekc_hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                set_error("EKC contains non-hex characters.");
                s_has_user_passcode = 0;
                return -1;
            }
            s_user_ekc[i] = (uint8_t)((hi << 4) | lo);
        }
        s_has_user_ekc = 1;
    }
    return 0;
}

/* Copy the user's EKC seeds into a title keyset. */
static void apply_user_ekc(struct keymgr_title_keyset* keyset) {
    memcpy(keyset->content_key_seed, s_user_ekc, KEYMGR_CONTENT_KEY_SIZE);
    memcpy(keyset->self_key_seed, s_user_ekc + KEYMGR_CONTENT_KEY_SIZE, KEYMGR_SELF_KEY_SIZE);
    keyset->flags.has_content_key_seed = 1;
    keyset->flags.has_self_key_seed    = 1;
}

/* ------------------------------------------------------------------ */
/* PFS options callback (--passcode from main.c, default all zeros)    */
/* ------------------------------------------------------------------ */

static int s_callback_count = 0;

static int ios_set_pfs_options(void* arg, struct pkg* pkg, struct pfs_options* opts) {
    UNUSED(arg);
    s_callback_count++;

    DIAG("=== ios_set_pfs_options CALL #%d ===", s_callback_count);
    DIAG("  pkg=%p  opts->keyset=%p", (void*)pkg, (void*)opts->keyset);

    if (opts->keyset) {
        if (s_has_user_passcode) {
            memcpy(opts->keyset->passcode, s_user_passcode, sizeof(opts->keyset->passcode));
            opts->keyset->flags.has_passcode = 1;
            DIAG("  -> Applied user passcode");
        } else if (!s_has_user_ekc) {
            /* An EKC derives the image key itself; a zero passcode would override it. */
            memset(opts->keyset->passcode, '0', sizeof(opts->keyset->passcode));
            opts->keyset->flags.has_passcode = 1;
            DIAG("  -> Applied zero passcode");
        }
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
/* Split PKGs: name_0.pkg, name_1.pkg, ...                            */
/*                                                                    */
/* The parts are plain byte-wise pieces of one package; part 0 holds  */
/* the header.  Any part's path resolves to the whole set.            */
/* ------------------------------------------------------------------ */

#define SPLIT_ERROR_PREFIX "Incomplete split PKG"   /* Swift matches on this */

struct split_name {
    char         prefix[4096];   /* path up to and including the '_'      */
    char         suffix[16];     /* ".pkg" as spelled in the file name    */
    unsigned int width;          /* digits to zero-pad to, 0 = unpadded   */
    unsigned int index;          /* part number of the path that was given */
};

/* "<prefix>_<digits>.pkg" -> split_name.  Returns 1 on a match. */
static int parse_split_name(const char* path, struct split_name* out) {
    size_t len = strlen(path);
    size_t dot, digits_end, digits_start, ndigits, i;
    unsigned long long idx = 0;

    if (len < 7 || len >= sizeof(out->prefix)) return 0;       /* "_0.pkg" */
    dot = len - 4;
    if (strcasecmp(path + dot, ".pkg") != 0) return 0;

    digits_end = dot;
    digits_start = digits_end;
    while (digits_start > 0 && path[digits_start - 1] >= '0' && path[digits_start - 1] <= '9')
        digits_start--;
    ndigits = digits_end - digits_start;
    if (ndigits == 0 || ndigits > 9 || digits_start == 0 || path[digits_start - 1] != '_') return 0;

    for (i = digits_start; i < digits_end; i++) idx = idx * 10 + (unsigned)(path[i] - '0');

    memcpy(out->prefix, path, digits_start);
    out->prefix[digits_start] = '\0';
    snprintf(out->suffix, sizeof(out->suffix), "%s", path + dot);
    out->width = (ndigits > 1 && path[digits_start] == '0') ? (unsigned)ndigits : 0;
    out->index = (unsigned)idx;
    return 1;
}

static void split_piece_path(const struct split_name* n, unsigned int index, char* out, size_t out_size) {
    snprintf(out, out_size, "%s%0*u%s", n->prefix, (int)n->width, index, n->suffix);
}

/*
 * Resolves pkg_path to the pieces it is part of.
 * Returns 1 if pkg_path belongs to a split PKG (set filled; set->complete says whether every
 * part is there), 0 if it is a standalone PKG file (set left empty).  Release with
 * pkg_free_piece_set().
 */
static int ios_resolve_pieces(const char* pkg_path, struct split_name* name, struct pkg_piece_set* set) {
    memset(set, 0, sizeof(*set));
    if (!parse_split_name(pkg_path, name)) return 0;
    if (!pkg_find_pieces(name->prefix, name->suffix, name->width, set)) return 0;   /* no part 0 */

    /* One file that already covers the whole package is just a PKG named "..._0.pkg". */
    if (set->count == 1 && set->complete) {
        pkg_free_piece_set(set);
        return 0;
    }
    return 1;
}

static void set_incomplete_error(const struct split_name* name, const struct pkg_piece_set* set) {
    char next[4096];
    char errbuf[8192];
    const char* base;

    split_piece_path(name, (unsigned int)set->count, next, sizeof(next));
    base = strrchr(next, '/');
    base = base ? base + 1 : next;

    snprintf(errbuf, sizeof(errbuf),
             SPLIT_ERROR_PREFIX ".\n"
             "Found %zu part(s) totaling %llu bytes, but the package needs %llu bytes.\n"
             "Next expected part: %s\n"
             "(or the last part that was copied is truncated).",
             set->count, (unsigned long long)set->total_size,
             (unsigned long long)set->required_size, base);
    set_error(errbuf);
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
    struct split_name  sname;
    struct pkg_piece_set set;
    const char* first_piece = pkg_path;
    int is_split = ios_resolve_pieces(pkg_path, &sname, &set);

    if (is_split) {
        if (!set.complete) {
            set_incomplete_error(&sname, &set);
            append_warn_log_to_error();
            pkg_free_piece_set(&set);
            return -1;
        }
        first_piece = set.paths[0];
        DIAG("Split PKG: %zu parts, %llu bytes", set.count, (unsigned long long)set.total_size);
    }

    if (!read_pkg_content_id(first_piece, content_id)) {
        char errbuf[8192];
        int n = snprintf(errbuf, sizeof(errbuf),
                         "Cannot open PKG or invalid magic.\nPath: %s\nErrno: %s",
                         first_piece, strerror(errno));
        if (!is_split && parse_split_name(pkg_path, &sname) && sname.index > 0 && n > 0 && (size_t)n < sizeof(errbuf)) {
            char part0[4096];
            split_piece_path(&sname, 0, part0, sizeof(part0));
            snprintf(errbuf + n, sizeof(errbuf) - (size_t)n,
                     "\nThis looks like part %u of a split PKG, but part 0 was not found:\n%s",
                     sname.index, part0);
        }
        set_error(errbuf);
        append_warn_log_to_error();
        pkg_free_piece_set(&set);
        return -1;
    }
    DIAG("PKG content_id = \"%s\"", content_id);

    if (!crypto_initialize()) {
        set_error("crypto_initialize failed.");
        append_warn_log_to_error();
        pkg_free_piece_set(&set);
        return -1;
    }
    if (!keymgr_initialize(config_path)) {
        set_error("keymgr_initialize failed.");
        append_warn_log_to_error();
        pkg_free_piece_set(&set);
        crypto_finalize();
        return -1;
    }

    /*
     * Pre-register a keyset carrying the EKC seeds.  pkg_alloc then takes its
     * "found keyset" path and runs setup_keyset_by_image_key() with the seeds
     * in place, which is what decrypts the EKPFS of finalized GD packages.
     */
    if (s_has_user_ekc) {
        struct keymgr_title_keyset* ks = keymgr_alloc_title_keyset(content_id, 1);
        if (ks) {
            apply_user_ekc(ks);
            DIAG("Registered user EKC for \"%s\"", content_id);
        }
    }

    if (is_split)
        *pkg_out = pkg_alloc_pieces((const char* const*)set.paths, set.count, ios_set_pfs_options, NULL);
    else
        *pkg_out = pkg_alloc(pkg_path, ios_set_pfs_options, NULL);
    pkg_free_piece_set(&set);

    if (!*pkg_out) {
        char errbuf[2048];
        snprintf(errbuf, sizeof(errbuf),
                 "pkg_alloc failed for: %s\n"
                 "Possible causes: wrong passcode/EKC, missing keys, corrupt PKG.",
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
/* SC0 entries (param.sfo, icons, etc. + extra entries)                */
/*                                                                     */
/* These live in the PKG entry table, not in the PFS image, so they    */
/* are enumerated separately and exposed to the UI as "Sc0/<name>".    */
/* Used for: listing, extract-all, and filtered extraction.            */
/* Best-effort: an entry that can't be read/decrypted is skipped.      */
/* ------------------------------------------------------------------ */

#define SC0_PREFIX      "Sc0/"
#define SC0_PREFIX_LEN  4

static int path_is_sc0(const char* p) {
    return p && strncmp(p, SC0_PREFIX, SC0_PREFIX_LEN) == 0;
}

struct ios_sc_ctx {
    /* extraction */
    const char*          output_directory;   /* "<out>/Sc0/"  (NULL when listing) */
    const char* const*   filter_paths;       /* NULL / 0 = everything */
    int                  filter_count;
    pkg_ios_progress_cb  progress_cb;
    void*                user_ctx;
    int                  extracted;
    /* listing with sizes (optional) */
    pkg_ios_list_cb      list_cb;
};

/* Locate data + keyset for an entry. Returns 1 if the entry is usable. */
static int ios_sc_entry_resolve(struct pkg* pkg, struct pkg_entry_desc* desc,
                                uint8_t** data, uint32_t* data_size,
                                uint64_t* data_offset, struct pkg_entry_keyset* keyset) {
    *data = pkg_locate_entry_data(pkg, desc->id, data_offset, data_size);
    if (!*data || *data_size == 0) return 0;

    if (desc->is_encrypted || desc->use_new_algo) {
        if (!pkg_get_entry_keyset(pkg, desc->id, keyset)) {
            DIAG("  SC entry '%s': no key, skipping", desc->name);
            return 0;
        }
    }
    return 1;
}

static int ios_sc_filter_allows(const struct ios_sc_ctx* ctx, const char* virt_path) {
    if (!ctx->filter_paths || ctx->filter_count <= 0) return 1;
    for (int i = 0; i < ctx->filter_count; i++)
        if (ctx->filter_paths[i] && strcmp(ctx->filter_paths[i], virt_path) == 0)
            return 1;
    return 0;
}

static enum cb_result ios_sc_entry_cb(void* arg, struct pkg* pkg,
                                      struct pkg_entry_desc* desc) {
    struct ios_sc_ctx* ctx = (struct ios_sc_ctx*)arg;
    char virt_path[4096], file_path[4096], directory[4096];
    struct pkg_entry_keyset keyset;
    uint8_t* data = NULL;
    uint8_t* out = NULL;
    uint32_t data_size = 0, data_size_aligned;
    uint64_t data_offset = 0;

    if (!ctx || !pkg || !desc) return CB_RESULT_CONTINUE;

    snprintf(virt_path, sizeof(virt_path), SC0_PREFIX "%s", desc->name);

    if (!ios_sc_entry_resolve(pkg, desc, &data, &data_size, &data_offset, &keyset))
        return CB_RESULT_CONTINUE;

    /* ---- listing mode ---- */
    if (ctx->list_cb) {
        ctx->list_cb(ctx->user_ctx, virt_path, (uint64_t)data_size, 0);
        return CB_RESULT_CONTINUE;
    }
    if (!ctx->output_directory) {           /* path-only listing (progress_cb) */
        if (ctx->progress_cb) ctx->progress_cb(ctx->user_ctx, virt_path);
        return CB_RESULT_CONTINUE;
    }

    /* ---- extraction mode ---- */
    if (!ios_sc_filter_allows(ctx, virt_path))
        return CB_RESULT_CONTINUE;

    snprintf(file_path, sizeof(file_path), "%s%s", ctx->output_directory, desc->name);
    path_get_directory(directory, sizeof(directory), file_path);
    if (*directory != '\0') make_directories(directory, 0755);

    data_size_aligned = align_up_32(data_size, 16);
    out = (uint8_t*)calloc(1, data_size_aligned);
    if (!out) return CB_RESULT_CONTINUE;

    if (desc->use_new_algo)
        aes_decrypt_oex(keyset.key, sizeof(keyset.key), data_offset, data, out, data_size);
    else if (desc->is_encrypted)
        aes_decrypt_cbc_cts(keyset.key, sizeof(keyset.key), keyset.iv, data, out, data_size_aligned);
    else
        memcpy(out, data, data_size);

    if (ctx->progress_cb) ctx->progress_cb(ctx->user_ctx, virt_path);

    if (write_to_file(file_path, out, data_size, NULL, 0644))
        ctx->extracted++;
    else
        DIAG("  SC entry '%s': write failed", desc->name);

    free(out);
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
    char tmp_dir[64]  = { 0 };   /* used only when list_only=1 */
    char tmp_image0[4096] = { 0 };

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
        /* Clean up temp dir if abort fired during listing */
        if (tmp_image0[0]) rmdir(tmp_image0);
        if (tmp_dir[0])    rmdir(tmp_dir);
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
        strncpy(tmp_dir, "/tmp/pkg_ios_list_XXXXXX", sizeof(tmp_dir) - 1);
        char* td = mkdtemp(tmp_dir);
        const char* enum_dir = td ? td : "/tmp";

        snprintf(tmp_image0, sizeof(tmp_image0), "%s/Image0", enum_dir);
        mkdir_p(tmp_image0);

        int ok = pfs_unpack_all(pkg->inner_pfs, tmp_image0, ios_list_pre_cb, &ctx);
        if (!ok) {
            set_error("pfs_unpack_all failed during file listing.");
            append_warn_log_to_error();
        } else {
            ret = 0;
            struct ios_sc_ctx sc_list;
            memset(&sc_list, 0, sizeof(sc_list));
            sc_list.progress_cb = progress_cb;
            sc_list.user_ctx    = cb_ctx;
            pkg_enum_entries(pkg, &ios_sc_entry_cb, &sc_list, 1);
        }

        /* Clean up temp dir (best-effort) */
        if (td) {
            rmdir(tmp_image0);
            rmdir(tmp_dir);
            tmp_image0[0] = '\0';
            tmp_dir[0]    = '\0';
        }
    } else {
        char image0[4096];
        int want_sc0 = (filter_count == 0);
        int want_pfs = (filter_count == 0);
        for (int i = 0; i < filter_count; i++) {
            if (path_is_sc0(filter_paths[i])) want_sc0 = 1;
            else                              want_pfs = 1;
        }

        snprintf(image0, sizeof(image0), "%s/Image0", output_dir);
        mkdir_p(output_dir);

        ret = 0;
        if (want_pfs) {
            mkdir_p(image0);
            DIAG("pfs_unpack_all -> %s", image0);
            if (!pfs_unpack_all(pkg->inner_pfs, image0, ios_unpack_pre_cb, &ctx)) {
                set_error("pfs_unpack_all failed — PKG data may be corrupt or incomplete.");
                append_warn_log_to_error();
                ret = -1;
            } else {
                DIAG("pfs_unpack_all OK");
            }
        }

        /* PKG system entries (+ extras) -> <out>/Sc0/.  Best-effort: never
         * turns a successful Image0 extraction into a failure. */
        if (want_sc0 && ret == 0) {
            char sc_dir[4096];
            snprintf(sc_dir, sizeof(sc_dir), "%s/Sc0/", output_dir);
            mkdir_p(sc_dir);

            struct ios_sc_ctx sc_ctx;
            memset(&sc_ctx, 0, sizeof(sc_ctx));
            sc_ctx.output_directory = sc_dir;
            sc_ctx.filter_paths     = filter_paths;
            sc_ctx.filter_count     = filter_count;
            sc_ctx.progress_cb      = progress_cb;
            sc_ctx.user_ctx         = cb_ctx;
            pkg_enum_entries(pkg, &ios_sc_entry_cb, &sc_ctx, 1 /* need_extra */);
            DIAG("SC entries extracted: %d", sc_ctx.extracted);
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

        /* Also list the PKG's own SC entries as "Sc0/<name>" so they can be
         * selected individually for filtered extraction. */
        struct ios_sc_ctx sc_list;
        memset(&sc_list, 0, sizeof(sc_list));
        sc_list.list_cb  = list_cb;
        sc_list.user_ctx = cb_ctx;
        pkg_enum_entries(pkg, &ios_sc_entry_cb, &sc_list, 1);
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

/* ------------------------------------------------------------------ */
/* Split PKG description (for UI)                                     */
/* ------------------------------------------------------------------ */

int pkg_ios_split_info(const char* pkg_path, int* out_parts,
                       uint64_t* out_total_size, int* out_complete) {
    struct split_name    name;
    struct pkg_piece_set set;
    int is_split;

    if (out_parts)      *out_parts = 1;
    if (out_total_size) *out_total_size = 0;
    if (out_complete)   *out_complete = 1;
    if (!pkg_path) return 0;

    is_split = ios_resolve_pieces(pkg_path, &name, &set);
    if (is_split) {
        if (out_parts)      *out_parts = (int)set.count;
        if (out_total_size) *out_total_size = set.total_size;
        if (out_complete)   *out_complete = set.complete;
    }
    pkg_free_piece_set(&set);
    return is_split;
}
