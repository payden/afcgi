dnl
dnl $Id$
dnl

PHP_ARG_ENABLE(afcgi,,
[  --disable-afcgi           Disable building AFCGI version of PHP
                          (this forces --without-pear)], yes, no)

AC_MSG_CHECKING(for AFCGI build)
if test "$PHP_AFCGI" != "no"; then
  PHP_ADD_MAKEFILE_FRAGMENT($abs_srcdir/sapi/afcgi/Makefile.frag)

  dnl Set filename
  SAPI_AFCGI_PATH=sapi/afcgi/afcgi

  dnl Select SAPI
  PHP_SELECT_SAPI(afcgi, program, afcgi.c,, '$(SAPI_AFCGI_PATH)')

  case $host_alias in
  *aix*)
    if test "$php_sapi_module" = "shared"; then
      BUILD_AFCGI="echo '\#! .' > php.sym && echo >>php.sym && nm -BCpg \`echo \$(PHP_GLOBAL_OBJS) \$(PHP_BINARY_OBJS) \$(PHP_AFCGI_OBJS) | sed 's/\([A-Za-z0-9_]*\)\.lo/.libs\/\1.o/g'\` | \$(AWK) '{ if (((\$\$2 == \"T\") || (\$\$2 == \"D\") || (\$\$2 == \"B\")) && (substr(\$\$3,1,1) != \".\")) { print \$\$3 } }' | sort -u >> php.sym && \$(LIBTOOL) --mode=link \$(CC) -export-dynamic \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) -Wl,-brtl -Wl,-bE:php.sym \$(PHP_RPATHS) \$(PHP_GLOBAL_OBJS) \$(PHP_AFCGI_OBJS) \$(EXTRA_LIBS) \$(ZEND_EXTRA_LIBS) -o \$(SAPI_AFCGI_PATH)"
    else
      BUILD_AFCGI="echo '\#! .' > php.sym && echo >>php.sym && nm -BCpg \`echo \$(PHP_GLOBAL_OBJS) \$(PHP_BINARY_OBJS) \$(PHP_AFCGI_OBJS) | sed 's/\([A-Za-z0-9_]*\)\.lo/\1.o/g'\` | \$(AWK) '{ if (((\$\$2 == \"T\") || (\$\$2 == \"D\") || (\$\$2 == \"B\")) && (substr(\$\$3,1,1) != \".\")) { print \$\$3 } }' | sort -u >> php.sym && \$(LIBTOOL) --mode=link \$(CC) -export-dynamic \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) -Wl,-brtl -Wl,-bE:php.sym \$(PHP_RPATHS) \$(PHP_GLOBAL_OBJS) \$(PHP_AFCGI_OBJS) \$(EXTRA_LIBS) \$(ZEND_EXTRA_LIBS) -o \$(SAPI_AFCGI_PATH)"
    fi
    ;;
  *darwin*)
    BUILD_AFCGI="\$(CC) \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) \$(NATIVE_RPATHS) \$(PHP_GLOBAL_OBJS:.lo=.o) \$(PHP_BINARY_OBJS:.lo=.o) \$(PHP_AFCGI_OBJS:.lo=.o) \$(PHP_FRAMEWORKS) \$(EXTRA_LIBS) \$(ZEND_EXTRA_LIBS) -o \$(SAPI_AFCGI_PATH)"
    ;;
  *netware*)
    BUILD_AFCGI="\$(LIBTOOL) --mode=link \$(CC) -export-dynamic \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) \$(PHP_RPATHS) \$(PHP_BINARY_OBJS) \$(PHP_AFCGI_OBJS) \$(EXTRA_LIBS) \$(ZEND_EXTRA_LIBS) -Lnetware -lphp5lib -o \$(SAPI_AFCGI_PATH)"
    ;;
  *)
    BUILD_AFCGI="\$(LIBTOOL) --mode=link \$(CC) -export-dynamic \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) \$(PHP_RPATHS) \$(PHP_GLOBAL_OBJS) \$(PHP_BINARY_OBJS) \$(PHP_AFCGI_OBJS) \$(EXTRA_LIBS) \$(ZEND_EXTRA_LIBS) -o \$(SAPI_AFCGI_PATH)"
    ;;
  esac

  dnl Set executable for tests
  PHP_EXECUTABLE="\$(top_builddir)/\$(SAPI_AFCGI_PATH)"
  PHP_SUBST(PHP_EXECUTABLE)

  dnl Expose to Makefile
  PHP_SUBST(SAPI_AFCGI_PATH)
  PHP_SUBST(BUILD_AFCGI)

  PHP_OUTPUT(sapi/afcgi/php.1)

  PHP_INSTALL_HEADERS([sapi/afcgi/afcgi.h])
fi
AC_MSG_RESULT($PHP_AFCGI)
