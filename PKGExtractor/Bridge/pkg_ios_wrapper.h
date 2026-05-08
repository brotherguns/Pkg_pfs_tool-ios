#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Progress callback — called before each file is extracted (or listed).
 * @param ctx      opaque pointer you passed to the function
 * @param path     relative path of the file (e.g. "usrdir/eboot.bin")
 */
typedef void (*pkg_ios_progress_cb)(void* ctx, const char* path);

/**
 * List callback with file size — called by pkg_ios_list_files_ex for each entry.
 * @param ctx   opaque pointer you passed to the function
 * @param path  relative path of the file or directory
 * @param size  file size in bytes (0 for directories)
 * @param is_dir 1 if directory, 0 if file
 */
typedef void (*pkg_ios_list_cb)(void* ctx, const char* path, uint64_t size, int is_dir);

/**
 * Extract a PS4 PKG file to a directory.
 *
 * @param pkg_path     absolute path to the .pkg file
 * @param output_dir   absolute path to the output directory (created if needed)
 * @param config_path  absolute path to the config.ini containing PS4 keys
 * @param progress_cb  called for each file extracted (may be NULL)
 * @param cb_ctx       passed verbatim to progress_cb
 *
 * @return  0 on success, -1 on failure. Call pkg_ios_last_error() for details.
 */
int pkg_ios_extract(
    const char*          pkg_path,
    const char*          output_dir,
    const char*          config_path,
    pkg_ios_progress_cb  progress_cb,
    void*                cb_ctx
);

/**
 * Extract a PS4 PKG file with an optional file filter.
 *
 * @param pkg_path      absolute path to the .pkg file
 * @param output_dir    absolute path to the output directory (created if needed)
 * @param config_path   absolute path to the config.ini containing PS4 keys
 * @param filter_paths  array of relative paths to extract (NULL = extract all)
 * @param filter_count  number of entries in filter_paths (0 = extract all)
 * @param progress_cb   called for each file extracted (may be NULL)
 * @param cb_ctx        passed verbatim to progress_cb
 *
 * @return  0 on success, -1 on failure. Call pkg_ios_last_error() for details.
 */
int pkg_ios_extract_filtered(
    const char*          pkg_path,
    const char*          output_dir,
    const char*          config_path,
    const char* const*   filter_paths,
    int                  filter_count,
    pkg_ios_progress_cb  progress_cb,
    void*                cb_ctx
);

/**
 * List all files inside a PKG without extracting them.
 * Calls list_cb(cb_ctx, path) for each file found.
 *
 * @param pkg_path    absolute path to the .pkg file
 * @param config_path absolute path to the config.ini
 * @param list_cb     called for every file path inside the PKG
 * @param cb_ctx      passed verbatim to list_cb
 *
 * @return  0 on success, -1 on failure. Call pkg_ios_last_error() for details.
 */
int pkg_ios_list_files(
    const char*          pkg_path,
    const char*          config_path,
    pkg_ios_progress_cb  list_cb,
    void*                cb_ctx
);

/** Human-readable description of the last error on the calling thread. */
const char* pkg_ios_last_error(void);

/**
 * List all files inside a PKG with file sizes, without extracting.
 * Uses pfs_enum_user_root_directory — passes path, byte size, and is_dir flag.
 *
 * @param pkg_path    absolute path to the .pkg file
 * @param config_path absolute path to the config.ini
 * @param list_cb     called for every entry inside the PKG
 * @param cb_ctx      passed verbatim to list_cb
 *
 * @return  0 on success, -1 on failure. Call pkg_ios_last_error() for details.
 */
int pkg_ios_list_files_ex(
    const char*       pkg_path,
    const char*       config_path,
    pkg_ios_list_cb   list_cb,
    void*             cb_ctx
);

/** Read the content_id from the PKG header without decrypting.
 *  @return 1 on success, 0 on failure. */
int pkg_ios_read_content_id(const char* pkg_path, char* out_buf, int buf_size);

#ifdef __cplusplus
}
#endif
