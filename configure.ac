#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.63)
AC_INIT([http-logger],[0.1],[kazimsarikaya@sanaldiyar.com])
AC_CONFIG_SRCDIR([src/http-logger.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE(http-logger,0.1)
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h malloc.h memory.h netinet/in.h stdlib.h syslog.h unistd.h],,
    AC_MSG_ERROR([Couldn't find main headers]))
AC_CHECK_HEADERS(pcap.h,,AC_MSG_ERROR([Couldn't find pcap.h]))
AC_CHECK_HEADERS(confuse.h,,AC_MSG_ERROR([Couldn't find confuse.h]))

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero inet_ntoa strstr pcap_lookupnet])

AC_OUTPUT
