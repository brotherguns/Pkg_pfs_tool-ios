#include "mapped_file.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifndef _WIN32
#	include <sys/mman.h>
#else
#	include "mingw/mman.h"
#endif

#ifdef __APPLE__
#	include <unistd.h>  /* pread / pwrite */
#endif

#define MAP_PAGE_ALIGNMENT 0x4000

struct file_map* map_files(const char* const* file_paths, size_t file_count) {
	struct file_map* map = NULL;
	struct stat64 st;
	void* data = MAP_FAILED;
	void* map_base_addr = MAP_FAILED;
	void* map_addr;
	int fd = -1;
	uint64_t file_size = 0;
	uint64_t total_file_size = 0;
	size_t i;

	assert(file_paths != NULL);

	map = (struct file_map*)malloc(sizeof(*map));
	if (!map)
		goto error;
	memset(map, 0, sizeof(*map));

	map->file_count = file_count;

	map->file_paths = (char**)malloc(file_count * sizeof(*map->file_paths));
	if (!map->file_paths)
		goto error;
	memset(map->file_paths, 0, file_count * sizeof(*map->file_paths));

	map->fds = (int*)malloc(file_count * sizeof(*map->fds));
	if (!map->fds)
		goto error;
	memset(map->fds, 0, file_count * sizeof(*map->fds));
	for (i = 0; i < file_count; ++i)
		map->fds[i] = -1;

	map->segments = (struct file_map_segment*)malloc(file_count * sizeof(*map->segments));
	if (!map->segments)
		goto error;
	memset(map->segments, 0, file_count * sizeof(*map->segments));
	for (i = 0; i < file_count; ++i)
		map->segments[i].base = MAP_FAILED;

	for (i = 0; i < file_count; ++i) {
		if (stat64(file_paths[i], &st) < 0)
			goto error;
		if (!S_ISREG(st.st_mode)) {
			errno = EINVAL;
			goto error;
		}

		file_size = (uint64_t)st.st_size;
		if (file_size > SIZE_MAX) {
			errno = EINVAL;
			goto error;
		}
		/*if ((file_size & (MAP_PAGE_ALIGNMENT - 1)) != 0) {
			errno = EINVAL;
			goto error;
		}*/

		map->segments[i].size = file_size;

		total_file_size += file_size;
	}

	/*
	 * Fast path: single file — just mmap it directly.
	 * Avoids the MAP_FIXED reserve-unmap-remap trick which is racy
	 * on iOS where the kernel aggressively reclaims unmapped pages.
	 */
	if (file_count == 1) {
		map->file_paths[0] = strdup(file_paths[0]);
		if (!map->file_paths[0])
			goto error;

		fd = open(file_paths[0], O_RDONLY | O_LARGEFILE | O_BINARY);
		if (fd < 0) {
			fprintf(stderr, "[DIAG] map_files: open() failed: %s  errno=%d (%s)\n",
			        file_paths[0], errno, strerror(errno));
			goto error;
		}

		if (fstat64(fd, &st) < 0) {
			fprintf(stderr, "[DIAG] map_files: fstat64() failed: errno=%d (%s)\n",
			        errno, strerror(errno));
			goto error;
		}
		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "[DIAG] map_files: not a regular file (mode=0%o)\n",
			        (unsigned)st.st_mode);
			errno = EINVAL;
			goto error;
		}

		file_size = (uint64_t)st.st_size;
		if (file_size != map->segments[0].size) {
			fprintf(stderr, "[DIAG] map_files: file size changed between stat calls: "
			        "%" PRIu64 " vs %" PRIu64 "\n",
			        file_size, map->segments[0].size);
			errno = EINVAL;
			goto error;
		}

		fprintf(stderr, "[DIAG] map_files: single-file fast path: size=%" PRIu64 "  path=%s\n",
		        file_size, file_paths[0]);

		data = mmap(NULL, (size_t)file_size, PROT_READ, MAP_SHARED, fd, 0);
		if (data == MAP_FAILED) {
			fprintf(stderr, "[DIAG] map_files: mmap() failed: errno=%d (%s)  size=%" PRIu64 "\n",
			        errno, strerror(errno), file_size);
#ifdef __APPLE__
			/*
			 * iOS refuses to mmap files larger than ~2 GB in a sideloaded app.
			 * Fall back to a pread-mode map: data stays NULL, use_pread=1.
			 * The fd is kept open; all I/O goes through map_pread().
			 */
			fprintf(stderr, "[DIAG] map_files: mmap failed — falling back to pread mode\n");
			map->fds[0]         = fd;
			map->segments[0].base = MAP_FAILED;  /* no mmap region */
			map->data           = NULL;
			map->size           = total_file_size;
			map->write          = 0;
			map->submap         = 0;
			map->use_pread      = 1;
			fd = -1;
			return map;
#else
			goto error;
#endif
		}

		/* Hint to the kernel: we'll read this sequentially — enables aggressive read-ahead */
#ifdef MADV_SEQUENTIAL
		madvise(data, (size_t)file_size, MADV_SEQUENTIAL);
#endif

		fprintf(stderr, "[DIAG] map_files: mmap OK: addr=%p  size=%" PRIu64 "\n",
		        data, file_size);

		/* Quick sanity: read first 4 bytes to confirm mapping is live */
		{
			uint8_t probe[4];
			memcpy(probe, data, 4);
			fprintf(stderr, "[DIAG] map_files: first 4 bytes: %02X %02X %02X %02X\n",
			        probe[0], probe[1], probe[2], probe[3]);
		}

		map->fds[0] = fd;
		map->segments[0].base = data;
		map->data = (uint8_t*)data;
		map->size = total_file_size;
		map->write = 0;
		map->submap = 0;

		fd = -1;
		data = MAP_FAILED;

		return map;
	}

	/* Multi-file path: reserve contiguous address space, then MAP_FIXED each piece. */
	file_size = total_file_size;
	data = mmap(NULL, (size_t)file_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (data == MAP_FAILED)
		goto error;
	map_base_addr = data;
	munmap(data, (size_t)file_size);
	data = NULL;

	for (i = 0, map_addr = map_base_addr; i < file_count; ++i) {
		map->file_paths[i] = strdup(file_paths[i]);
		if (!map->file_paths[i])
			goto error;

		fd = open(file_paths[i], O_RDONLY | O_LARGEFILE | O_BINARY);
		if (fd < 0)
			goto error;

		if (fstat64(fd, &st) < 0)
			goto error;
		if (!S_ISREG(st.st_mode)) {
			errno = EINVAL;
			goto error;
		}

		file_size = (uint64_t)st.st_size;
		if (file_size != map->segments[i].size) {
			errno = EINVAL;
			goto error;
		}

		data = mmap(map_addr, (size_t)file_size, PROT_READ, MAP_FIXED | MAP_SHARED, fd, 0);
		if (data == MAP_FAILED)
			goto error;
		if (data != map_addr) {
			errno = EINVAL;
			goto error;
		}

		map->fds[i] = fd;
		map->segments[i].base = data;

 		map_addr = (uint8_t*)map_addr + file_size;

		fd = -1;
		data = MAP_FAILED;
	}

	map->data = (uint8_t*)map_base_addr;
	map->size = total_file_size;
	map->write = 0;
	map->submap = 0;

	return map;

error:
	unmap_file(map);

	if (data != MAP_FAILED)
		munmap(data, (size_t)file_size);

	if (fd > 0)
		close(fd);

	return NULL;
}

struct file_map* map_file(const char* file_path) {
	return map_files(&file_path, 1);
}

struct file_map* map_file_for_write(const char* file_path, uint64_t file_size, int mode) {
	struct file_map* map = NULL;
	int fd = -1;
	void* data = MAP_FAILED;
	size_t file_count = 1;
	size_t i;

	assert(file_path != NULL);

	map = (struct file_map*)malloc(sizeof(*map));
	if (!map)
		goto error;
	memset(map, 0, sizeof(*map));

	map->file_count = file_count;

	map->file_paths = (char**)malloc(file_count * sizeof(*map->file_paths));
	if (!map->file_paths)
		goto error;
	memset(map->file_paths, 0, file_count * sizeof(*map->file_paths));

	map->file_paths[0] = strdup(file_path);
	if (!map->file_paths[0])
		goto error;

	map->fds = (int*)malloc(file_count * sizeof(*map->fds));
	if (!map->fds)
		goto error;
	memset(map->fds, 0, file_count * sizeof(*map->fds));
	for (i = 0; i < file_count; ++i)
		map->fds[i] = -1;

	map->segments = (struct file_map_segment*)malloc(file_count * sizeof(*map->segments));
	if (!map->segments)
		goto error;
	memset(map->segments, 0, file_count * sizeof(*map->segments));
	for (i = 0; i < file_count; ++i)
		map->segments[i].base = MAP_FAILED;

	//map->segments[0].size = file_size * 2; // FIXME: wtf?
	map->segments[0].size = file_size;

	fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE | O_BINARY, mode);
	if (fd < 0)
		goto error;
	if (ftruncate64(fd, (fileoff_t)map->segments[0].size) < 0)
		goto error;

	data = mmap(NULL, (size_t)map->segments[0].size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED)
		goto error;

	map->fds[0] = fd;
	map->segments[0].base = data;
	map->data = (uint8_t*)data;
	map->size = map->segments[0].size;
	map->offset = 0;
	map->write = 1;
	map->submap = 0;

	return map;

error:
	unmap_file(map);

	if (data != MAP_FAILED)
		munmap(data, (size_t)file_size);

	if (fd > 0)
		close(fd);

	return NULL;
}

struct file_map* map_file_sub_region(struct file_map* map, uint64_t offset, uint64_t size) {
	struct file_map* submap = NULL;

	if (!map)
		goto error;

	if (map->offset + offset + size > map->size)
		goto error;

	submap = (struct file_map*)malloc(sizeof(*submap));
	if (!submap)
		goto error;
	memset(submap, 0, sizeof(*submap));

	submap->file_count = map->file_count;
	submap->file_paths = map->file_paths;
	submap->fds = map->fds;
	submap->segments = map->segments;
	submap->data = map->data + offset;
	submap->size = size;
	submap->offset = offset;
	submap->write = map->write;
	submap->submap = 1;

	return submap;

error:
	unmap_file(submap);

	return NULL;
}

void unmap_file(struct file_map* map) {
	size_t i;

	if (!map)
		return;

	if (!map->submap) {
		if (map->segments) {
			for (i = 0; i < map->file_count; ++i) {
				if (map->segments[i].base != MAP_FAILED) {
					if (map->write)
						msync(map->segments[i].base, (size_t)map->segments[i].size, MS_SYNC);
					munmap(map->segments[i].base, (size_t)map->segments[i].size);
				}
			}

			free(map->segments);
		}

		if (map->fds) {
			for (i = 0; i < map->file_count; ++i) {
				if (map->fds[i] > 0)
					close(map->fds[i]);
			}

			free(map->fds);
		}

		if (map->file_paths) {
			for (i = 0; i < map->file_count; ++i) {
				if (map->file_paths[i])
					free(map->file_paths[i]);
			}

			free(map->file_paths);
		}
	}

	free(map);
}

#ifdef __APPLE__
/*
 * map_pread / map_pwrite — used when map->use_pread == 1.
 *
 * Reads/writes exactly `n` bytes at absolute file offset `off`.
 * Returns 1 on success, 0 on any short read/write or error.
 */
int map_pread(const struct file_map* map, void* buf, uint64_t n, uint64_t off) {
	uint8_t* dst = (uint8_t*)buf;
	uint64_t remaining = n;
	off_t file_off = (off_t)(map->offset + off);

	assert(map != NULL);
	assert(map->use_pread);
	assert(map->fds != NULL && map->fds[0] >= 0);

	while (remaining > 0) {
		ssize_t got = pread(map->fds[0], dst, (size_t)remaining, file_off);
		if (got <= 0) {
			fprintf(stderr, "[DIAG] map_pread: pread failed: off=%" PRIu64 " n=%" PRIu64 " errno=%d (%s)\n",
			        (uint64_t)file_off, n, errno, strerror(errno));
			return 0;
		}
		dst      += got;
		file_off += got;
		remaining -= (uint64_t)got;
	}
	return 1;
}

int map_pwrite(const struct file_map* map, const void* buf, uint64_t n, uint64_t off) {
	const uint8_t* src = (const uint8_t*)buf;
	uint64_t remaining = n;
	off_t file_off = (off_t)(map->offset + off);

	assert(map != NULL);
	assert(map->use_pread);
	assert(map->fds != NULL && map->fds[0] >= 0);

	while (remaining > 0) {
		ssize_t wrote = pwrite(map->fds[0], src, (size_t)remaining, file_off);
		if (wrote <= 0) {
			fprintf(stderr, "[DIAG] map_pwrite: pwrite failed: off=%" PRIu64 " n=%" PRIu64 " errno=%d (%s)\n",
			        (uint64_t)file_off, n, errno, strerror(errno));
			return 0;
		}
		src      += wrote;
		file_off += wrote;
		remaining -= (uint64_t)wrote;
	}
	return 1;
}
#else
/* Stub for non-Apple: use_pread is never set, these should never be called. */
int map_pread(const struct file_map* map, void* buf, uint64_t n, uint64_t off) {
	(void)map; (void)buf; (void)n; (void)off;
	assert(0 && "map_pread called on non-Apple platform");
	return 0;
}
int map_pwrite(const struct file_map* map, const void* buf, uint64_t n, uint64_t off) {
	(void)map; (void)buf; (void)n; (void)off;
	assert(0 && "map_pwrite called on non-Apple platform");
	return 0;
}
#endif
