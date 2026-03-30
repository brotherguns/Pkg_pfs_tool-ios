#pragma once
#include <setjmp.h>

/* Thread-local state — defined in pkg_ios_wrapper.c */
extern _Thread_local jmp_buf g_pkg_abort_jmp;
extern _Thread_local int     g_pkg_abort_active;
extern _Thread_local char    g_pkg_abort_msg[512];

/* Called by util_ios.c's error() instead of exit() */
void pkg_ios_abort(const char* message);
