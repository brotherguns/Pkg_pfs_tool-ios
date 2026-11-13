#include "mapped_file.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifndef _WIN32
#	include <sys/mman.h>
#else
#	include "mingw/mman.h"
#endif

/*
 * pread mode: inputs are read with pread() instead of being mmap'd.  Always the
 * case for split (multi-file) inputs on Apple, where iOS refuses very large
 * mappings.  PFS_MAP_FORCE_PREAD enables the same code on other hosts (tests).
 */
#if defined(__APPLE__) || defined(PFS_MAP_FORCE_PREAD)
#	define MAP_HAVE_PREAD 1
#endif

#ifdef MAP_HAVE_PREAD
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
#ifdef MAP_HAVE_PREAD
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

#ifdef MAP_HAVE_PREAD
	/*
	 * Split input: never mmap.  The reserve/unmap/MAP_FIXED trick below is racy
	 * on iOS and the combined size is beyond what an iOS app may map.  Open every
	 * piece and let map_pread() walk the segments.
	 */
	if (file_count > 1) {
		for (i = 0; i < file_count; ++i) {
			map->file_paths[i] = strdup(file_paths[i]);
			if (!map->file_paths[i])
				goto error;

			fd = open(file_paths[i], O_RDONLY | O_LARGEFILE | O_BINARY);
			if (fd < 0) {
				fprintf(stderr, "[DIAG] map_files: open() failed: %s  errno=%d (%s)\n",
				        file_paths[i], errno, strerror(errno));
				goto error;
			}

			if (fstat64(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
			    (uint64_t)st.st_size != map->segments[i].size) {
				fprintf(stderr, "[DIAG] map_files: piece %zu changed or not a regular file: %s\n",
				        i, file_paths[i]);
				errno = EINVAL;
				goto error;
			}

			map->fds[i] = fd;
			fd = -1;
		}

		fprintf(stderr, "[DIAG] map_files: split input, %zu pieces, total=%" PRIu64 " (pread mode)\n",
		        file_count, total_file_size);

		map->data      = NULL;
		map->size      = total_file_size;
		map->write     = 0;
		map->submap    = 0;
		map->use_pread = 1;

		return map;
	}
#endif

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
	submap->use_pread = map->use_pread;

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

#ifdef MAP_HAVE_PREAD
/*
 * map_pread / map_pwrite — used when map->use_pread == 1.
 *
 * Read/write exactly `n` bytes at absolute offset `off` of the (possibly
 * multi-file) input.  A request may span several pieces; each piece is
 * addressed through its own fd.  Returns 1 on success, 0 on error or when the
 * range runs past the end of the last piece.
 */
static int map_rw(const struct file_map* map, void* buf, uint64_t n, uint64_t off, int write) {
	uint8_t* p = (uint8_t*)buf;
	uint64_t pos = map->offset + off;
	uint64_t seg_start = 0;
	size_t i;

	assert(map != NULL);
	assert(map->use_pread);
	assert(map->fds != NULL && map->segments != NULL);

	for (i = 0; i < map->file_count && n > 0; ++i) {
		uint64_t seg_end = seg_start + map->segments[i].size;

		if (pos < seg_end) {
			uint64_t chunk = MIN(n, seg_end - pos);
			uint64_t seg_off = pos - seg_start;

			while (chunk > 0) {
				/* Darwin pread/pwrite reject counts above INT_MAX. */
				size_t want = (size_t)MIN(chunk, (uint64_t)1 << 30);
				ssize_t r = write ? pwrite(map->fds[i], p, want, (off_t)seg_off)
				                  : pread(map->fds[i], p, want, (off_t)seg_off);
				if (r <= 0) {
					fprintf(stderr, "[DIAG] map_p%s: failed: piece=%zu off=%" PRIu64 " n=%zu errno=%d (%s)\n",
					        write ? "write" : "read", i, seg_off, want, errno, strerror(errno));
					return 0;
				}
				p += r;
				pos += (uint64_t)r;
				seg_off += (uint64_t)r;
				chunk -= (uint64_t)r;
				n -= (uint64_t)r;
			}
		}

		seg_start = seg_end;
	}

	return n == 0;
}

int map_pread(const struct file_map* map, void* buf, uint64_t n, uint64_t off) {
	return map_rw(map, buf, n, off, 0);
}

int map_pwrite(const struct file_map* map, const void* buf, uint64_t n, uint64_t off) {
	return map_rw(map, (void*)buf, n, off, 1);
}
#else
/* Stub for hosts without pread mode: use_pread is never set, these should never be called. */
int map_pread(const struct file_map* map, void* buf, uint64_t n, uint64_t off) {
	(void)map; (void)buf; (void)n; (void)off;
	assert(0 && "map_pread called without pread mode");
	return 0;
}
int map_pwrite(const struct file_map* map, const void* buf, uint64_t n, uint64_t off) {
	(void)map; (void)buf; (void)n; (void)off;
	assert(0 && "map_pwrite called without pread mode");
	return 0;
}
#endif
