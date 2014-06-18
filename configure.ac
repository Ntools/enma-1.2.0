# Copyright (c) 2006-2011 Internet Initiative Japan Inc. All rights reserved.
#
# The terms and conditions of the accompanying program
# shall be provided separately by Internet Initiative Japan Inc.
# Any use, reproduction or distribution of the program are permitted
# provided that you agree to be bound to such terms and conditions.
#
# $Id: configure.ac 1480 2012-01-30 08:03:26Z takahiko $

AC_INIT(enma, 1.2.0)
AC_CONFIG_SRCDIR(enma/src/enma.c)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AH_VERBATIM([_GNU_SOURCE],
[/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif])

AC_CHECK_HEADERS(sys/prctl.h net/if_dl.h)
AC_CHECK_FUNCS(prctl)

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_pton, nsl)

AC_ARG_ENABLE(debug,
	AC_HELP_STRING(--enable-debug, [enable debugging]),
	[CFLAGS="$CFLAGS -g3 -O0"],
	[CFLAGS="$CFLAGS -g -O2"])

AC_ARG_WITH(libmilter-libdir,
	AC_HELP_STRING(--with-libmilter-libdir=DIR, [specify where to find libmilter library]),
	[LDFLAGS="$LDFLAGS -L$withval"])

AC_ARG_WITH(libmilter-incdir,
	AC_HELP_STRING(--with-libmilter-incdir=DIR, [specify where to find libmilter header files]),
	[CPPFLAGS="$CPPFLAGS -I$withval"])

AC_ARG_WITH(libmilter,
	AC_HELP_STRING(--with-libmilter=DIR, [specify libmilter base directory]),
	[CPPFLAGS="$CPPFLAGS -I$withval/include" LDFLAGS="$LDFLAGS -L$withval/lib"],
	[CPPFLAGS="$CPPFLAGS -I/usr/local/include" LDFLAGS="$LDFLAGS -L/usr/local/lib"])

AC_ARG_WITH(libbind-libdir,
	AC_HELP_STRING(--with-libbind-libdir=DIR, [specify where to find libbind library]),
	[LDFLAGS="$LDFLAGS -L$withval"])

AC_ARG_WITH(libbind-incdir,
	AC_HELP_STRING(--with-libbind-incdir=DIR, [specify where to find libbind header files]),
	[CPPFLAGS="$CPPFLAGS -I$withval"])

AC_ARG_WITH(libbind,
	AC_HELP_STRING(--with-libbind=DIR, [specify libbind base directory]),
	[CPPFLAGS="$CPPFLAGS -I$withval/include/bind" LDFLAGS="$LDFLAGS -L$withval/lib"])

AC_ARG_WITH(ldns-libdir,
	AC_HELP_STRING(--with-ldns-libdir=DIR, [specify where to find ldns library]),
	[LDFLAGS="$LDFLAGS -L$withval"])

AC_ARG_WITH(ldns-incdir,
	AC_HELP_STRING(--with-ldns-incdir=DIR, [specify where to find ldns header files]),
	[CPPFLAGS="$CPPFLAGS -I$withval"])

AC_ARG_WITH(ldns,
	AC_HELP_STRING(--with-ldns=DIR, [specify ldns base directory]),
	[CPPFLAGS="$CPPFLAGS -I$withval/include" LDFLAGS="$LDFLAGS -L$withval/lib"])

AC_ARG_WITH(ssl-libdir,
	AC_HELP_STRING(--with-ssl-libdir=DIR, [specify where to find OpenSSL library]),
	[LDFLAGS="$LDFLAGS -L$withval"])

AC_ARG_WITH(ssl-incdir,
	AC_HELP_STRING(--with-ssl-incdir=DIR, [specify where to find OpenSSL header files]),
	[CPPFLAGS="$CPPFLAGS -I$withval"])

AC_ARG_WITH(ssl,
	AC_HELP_STRING(--with-ssl=DIR, [specify OpenSSL base directory]),
	[CPPFLAGS="$CPPFLAGS -I$withval/include" LDFLAGS="$LDFLAGS -L$withval/lib"],
	[CPPFLAGS="$CPPFLAGS -I/usr/local/include" LDFLAGS="$LDFLAGS -L/usr/local/lib"])

CFLAGS="$CFLAGS -std=gnu99 -Wall -Wextra"
CPPFLAGS="$CPPFLAGS -I$includedir -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS"
LDFLAGS="$LDFLAGS -L$libdir -lpthread"

AC_ARG_WITH(resolver,
	AC_HELP_STRING(--with-resolver, [resolver library (ldns or libbind)]),
	[
	 if test x${withval} = xlibbind; then
		RESOLVER_SRC="bindresolver.c"; MILTER_LIBS="-lbind";
		dnl libbind built on Solaris 8 or later depends libmd5
		AC_SEARCH_LIBS(MD5Init, md5)
		AC_SEARCH_LIBS(clock_gettime, rt)
		AC_CHECK_LIB(bind, __res_ndestroy,
			[],
			[AC_MSG_ERROR(libbind not found)])
	 elif test x${withval} = xlibresolv; then
		RESOLVER_SRC="bindresolver.c";
		AC_DEFINE(USE_LIBRESOLV, [1], [Define to 1 to link with libresolv AT YOUR OWN RISK (NOT RECOMMENDED)])
		AC_SEARCH_LIBS(ns_initparse, resolv,
			[true],
			AC_SEARCH_LIBS(__ns_initparse, resolv,
				[true],
				dnl Ugly but no other way. Let me know if you know a better way.
				[RESOLVER_LIBS="/usr/lib/libresolv.a"]
			)
		)
	 else
		RESOLVER_SRC="ldnsresolver.c";
		AC_CHECK_LIB(ldns, ldns_resolver_new,
			[],
			[AC_MSG_ERROR(libldns not found)])
	 fi
	],
	[
	RESOLVER_SRC="ldnsresolver.c";
	AC_CHECK_LIB(ldns, ldns_resolver_new,
		[],
		[AC_MSG_ERROR(libldns not found)])
	]
)

AC_CHECK_LIB(milter, smfi_main,
	[true],     dnl skip default action
	[AC_MSG_ERROR(libmilter not found)], [${MILTER_LIBS}])

AC_CHECK_LIB(crypto, EVP_DigestInit,
	[],
	[AC_MSG_ERROR(libcrypto not found)])

AC_SUBST(RESOLVER_SRC)
AC_SUBST(RESOLVER_LIBS)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile libsauth/Makefile enma/Makefile)

AC_OUTPUT
