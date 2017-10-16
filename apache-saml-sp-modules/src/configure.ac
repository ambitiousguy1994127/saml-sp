#
# mod_saml_sp - Apache module for OpenIAM authentication
#
AC_PREREQ([2.69])
AC_INIT([mod_saml_sp], [0.9], [https://github.com/OpenIAM/saml-sp], [mod_saml_sp])
AC_CONFIG_AUX_DIR(scripts)
AM_INIT_AUTOMAKE
dnl AM_MAINTAINER_MODE([disable])
AC_PREFIX_DEFAULT(/usr)

# Check for required programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PATH_PROG(CP, cp)
AC_PATH_PROG(APXS, apxs, "no", [/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/local/apache/bin])
AC_PATH_PROG(APXS2, apxs2, "no", [/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/local/apache/bin])
[test x"$APXS2" = "xno" -a x"$APXS" = "xno" && ] AC_MSG_ERROR([cannot find apxs or apxs2])
[test x"$APXS2" != "xno" && APXS="$APXS2"]

# Add GCC flags
[GCC_WARN_FLAGS=""
CFLAGS=""
if test x"$GCC" = "xyes"; then
    GCC_WARN_FLAGS="-Wall -Waggregate-return -Wcast-align -Wchar-subscripts -Wcomment -Wformat \
        -Wimplicit -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wno-long-long \
        -Wparentheses -Wpointer-arith -Wredundant-decls -Wreturn-type -Wswitch -Wtrigraphs \
        -Wuninitialized -Wunused -Wwrite-strings -Wshadow -Wstrict-prototypes -Wcast-qual"
    CFLAGS="-O3 $GCC_WARN_FLAGS"
fi]
AC_SUBST(GCC_WARN_FLAGS)
AC_SUBST(CFLAGS)


# Checks for libraries
PKG_CHECK_MODULES([Dependencies],  [libxml-2.0 >= 2.6 xmlsec1-openssl >= 1.2.20])

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp strstr])

AC_ARG_VAR([ErrorDocument], [ErrorDocument location Default is /var/www/html])
AS_IF([test "x$ErrorDocument" = x], [ErrorDocument="/var/www/html"])

LIBXML_CFLAGS=`xml2-config --cflags`
LIBXML_LIBS=`xml2-config --libs`

XMLSEC_CFLAGS="-I/usr/include -I/usr/include/xmlsec1 -I/usr/local/include/xmlsec1 -DXMLSEC_NO_SIZE_T -DXMLSEC_CRYPTO_OPENSSL=1 -DXMLSEC_NO_XSLT=1"
XMLSEC_LIBS="-L/usr/local/lib -L/usr/lib64 -L/usr/lib -lxmlsec1 -lxml2 -lxmlsec1-openssl -lz"

LIBS="$LIBS $LIBXML_LIBS $XMLSEC_LIBS"
CFLAGS="$CFLAGS $LIBXML_CFLAGS $XMLSEC_CFLAGS"

# Generated files
AC_CONFIG_FILES(Makefile)

# Go
AC_OUTPUT