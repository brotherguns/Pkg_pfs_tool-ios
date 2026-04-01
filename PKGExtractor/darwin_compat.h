/*
 * darwin_compat.h
 * Force-included into every pkg_pfs_tool .c file on Apple builds.
 * Maps Linux-only symbols to their Darwin equivalents.
 */
#pragma once

#ifdef __APPLE__
#  include <sys/stat.h>
#  include <sys/mman.h>
#  include <unistd.h>

/* On Darwin arm64, off_t is already 64-bit — stat == stat64 */
#  define stat64         stat
#  define fstat64        fstat
#  define lstat64        lstat
#  define ftruncate64    ftruncate

/* MAP_ANONYMOUS is MAP_ANON on Darwin */
#  ifndef MAP_ANONYMOUS
#    define MAP_ANONYMOUS MAP_ANON
#  endif

/* O_LARGEFILE is a no-op on Darwin */
#  ifndef O_LARGEFILE
#    define O_LARGEFILE 0
#  endif

#endif /* __APPLE__ */
