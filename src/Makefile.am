bin_PROGRAMS = httpd xspasswd clearxs readxs xsindex httpdc
cgi_PROGRAMS = xschpass imagemap error gfxcount
noinst_PROGRAMS = reformatxs xscat
noinst_LIBRARIES = libxs.a

httpd_SOURCES = httpd.c cgi.c convert.c local.c methods.c ssi.c ssl.c fcgi.c
error_SOURCES = error.c local.c

libxs_a_SOURCES = authenticate.c decode.c extra.c path.c pcre.c xscrypt.c
if LDAP
httpd_SOURCES += ldap.c 
endif
libxs_a_LIBADD = @LIBOBJS@		# AC_REPLACE_FUNS sources
libxs_a_CFLAGS = @libxs_cflags@

httpd_CFLAGS = @httpd_cflags@ -DBUILD_HTTPD
httpd_LDFLAGS = @httpd_ldflags@ @libxs_ldflags@
xspasswd_LDFLAGS = @libxs_ldflags@
xschpass_LDFLAGS = @libxs_ldflags@
LDADD = libxs.a				# default for all *_PROGRAMS
DEFAULT_INCLUDES =

EXTRA_DIST = alternative.h authenticate.h cgi.h config.h confpatch.h \
	confuser.h convert.h decode.h digcalc.h extra.h \
	fcgi.h fcgi_api.h htconfig.h httpd.h \
	ldap.h local.h md5.h methods.h path.h pcre.h \
	ssi.h ssl.h xscounter.h xscrypt.h

EXTRA_DIST += digcalc.c ldap.c

cscope:
	@cscope -bqv
