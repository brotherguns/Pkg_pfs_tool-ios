#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Progress callback — called before each file is extracted.
 * @param ctx      opaque pointer you passed to pkg_ios_extract()
 * @param path     relative path of the file being extracted (e.g. "usrdir/eboot.bin")
 */
typedef void (*pkg_ios_progress_cb)(void* ctx, const char* path);

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

/** Human-readable description of the last error on the calling thread. */
const char* pkg_ios_last_error(void);

#ifdef __cplusplus
}
#endif
