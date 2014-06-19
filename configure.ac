AC_INIT([reptyr], [0.5])
AM_SILENT_RULES([yes])
AC_CONFIG_LIBOBJ_DIR([compat])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign no-define subdir-objects])

AC_PROG_CC
AC_LANG_C

AC_PROG_MAKE_SET
AC_PROG_INSTALL

AC_HEADER_STDC
AC_HEADER_STAT
AC_HEADER_SYS_WAIT

AC_CHECK_DECLS(reallocarray)
AC_REPLACE_FUNCS(reallocarray)

AH_BOTTOM([#ifndef HAVE_REALLOCARRAY
void *
reallocarray(void *optr, size_t nmemb, size_t size);
#endif
])


AC_OUTPUT([Makefile])
