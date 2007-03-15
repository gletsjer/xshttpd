bin_PROGRAMS = httpd xspasswd clearxs readxs xsindex httpdc
cgi_PROGRAMS = xschpass imagemap error gfxcount
noinst_PROGRAMS = reformatxs xscat
noinst_LIBRARIES = libxs.a

httpd_SOURCES = httpd.c authenticate.c cgi.c convert.c fcgi.c \
	local.c methods.c pcre.c ssi.c ssl.c
if LDAP
httpd_SOURCES += ldap.c 
endif
httpd_CFLAGS = @httpd_cflags@ -DBUILD_HTTPD
httpd_LDFLAGS = @httpd_ldflags@ @libxs_ldflags@

libxs_a_SOURCES = decode.c extra.c local.c path.c xscrypt.c
libxs_a_CFLAGS = @libxs_cflags@

xspasswd_LDFLAGS = @libxs_ldflags@
xschpass_LDFLAGS = @libxs_ldflags@

# default for all *_PROGRAMS
LDADD = libxs.a ../libcompat/libcompat.a
DEFAULT_INCLUDES =

EXTRA_DIST = alternative.h authenticate.h cgi.h config.h confpatch.h \
	confuser.h convert.h decode.h digcalc.h extra.h \
	fcgi.h fcgi_api.h htconfig.h httpd.h \
	ldap.h local.h md5.h methods.h path.h pcre.h \
	ssi.h ssl.h xscounter.h xscrypt.h

EXTRA_DIST += digcalc.c ldap.c

cscope:
	@cscope -bqv
