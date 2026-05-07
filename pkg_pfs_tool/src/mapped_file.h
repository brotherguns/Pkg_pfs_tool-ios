#pragma once

#include "common.h"

struct file_map_segment {
	void* base;
	uint64_t size;
};

struct file_map {
	char** file_paths;
	size_t file_count;
	uint64_t offset, size;
	int* fds;
	struct file_map_segment* segments;
	uint8_t* data;
	int write;
	int submap;
	/*
	 * use_pread: set on __APPLE__ when the file is too large to mmap.
	 * map->data is NULL; all reads go through map_pread() / map_pwrite().
	 * Only valid for single-file, read-only maps (PKG input files).
	 */
	int use_pread;
};

struct file_map* map_files(const char* const* file_paths, size_t file_count);
struct file_map* map_file(const char* file_path);
struct file_map* map_file_for_write(const char* file_path, uint64_t file_size, int mode);
struct file_map* map_file_sub_region(struct file_map* map, uint64_t offset, uint64_t size);
void unmap_file(struct file_map* map);

/*
 * map_pread / map_pwrite — used when use_pread == 1.
 * Reads/writes exactly `n` bytes at absolute file offset `off`
 * (relative to the start of the mapped file, NOT map->offset).
 * Returns 1 on success, 0 on error.
 */
int map_pread(const struct file_map* map, void* buf, uint64_t n, uint64_t off);
int map_pwrite(const struct file_map* map, const void* buf, uint64_t n, uint64_t off);
