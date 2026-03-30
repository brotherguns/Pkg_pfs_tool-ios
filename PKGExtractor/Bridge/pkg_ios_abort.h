#pragma once
#include <setjmp.h>

/* Thread-local state — defined in pkg_ios_wrapper.c */
extern _Thread_local jmp_buf g_pkg_abort_jmp;
extern _Thread_local int     g_pkg_abort_active;
extern _Thread_local char    g_pkg_abort_msg[512];

/* Warning log — captures all warning() calls during extraction */
extern _Thread_local char    g_pkg_warn_log[4096];

/* Called by util_ios.c's error() instead of exit() */
void pkg_ios_abort(const char* message);

/* Called by util_ios.c's warning() to append to the warn log */
void pkg_ios_log_warning(const char* message);
