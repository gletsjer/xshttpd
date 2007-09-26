bin_PROGRAMS = httpd xspasswd clearxs readxs xsindex httpdc
cgi_PROGRAMS = imagemap error gfxcount xschpass
noinst_PROGRAMS = reformatxs xscat
noinst_LIBRARIES = libxs.a
AM_CPPFLAGS = -DHTTPD_ROOT=\"$(rootdir)\"

httpd_SOURCES = httpd.c authenticate.c cgi.c cloader.c convert.c \
	ldap.c methods.c path.c pcre.c ssi.c ssl.c xsfiles.c
httpd_CFLAGS = @httpd_cflags@ -DBUILD_HTTPD
httpd_LDFLAGS = @httpd_ldflags@ @libxs_ldflags@

libxs_a_SOURCES = decode.c extra.c path.c xscrypt.c
libxs_a_CFLAGS = @libxs_cflags@

# default for all *_PROGRAMS
LDADD = libxs.a ../libcompat/libcompat.a @libxs_ldflags@
DEFAULT_INCLUDES =

EXTRA_DIST = alternative.h authenticate.h cgi.h cloader.h config.h \
	confpatch.h confuser.h convert.h decode.h digcalc.h extra.h \
	fcgi.h fcgi_api.h htconfig.h httpd.h \
	ldap.h methods.h path.h pcre.h \
	ssi.h ssl.h xsfiles.h xscounter.h xscrypt.h

EXTRA_DIST += digcalc.c fcgi.c

cscope:
	@cscope -bqv
