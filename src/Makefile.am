bin_PROGRAMS = httpd xspasswd clearxs readxs xsindex httpdc
cgi_PROGRAMS = xschpass imagemap error gfxcount
noinst_LIBRARIES = libxs.a

httpd_SOURCES = httpd.c cgi.c convert.c local.c methods.c ssi.c
error_SOURCES = error.c local.c

libxs_a_SOURCES = extra.c path.c procname.c xscrypt.c
if MD5
	libxs_a_SOURCES += digcalc.c 
endif
libxs_a_LIBADD = @LIBOBJS@		# AC_REPLACE_FUNS sources

httpd_CFLAGS = @httpd_cflags@ -DBUILD_HTTPD
httpd_LDFLAGS = @httpd_ldflags@ @ldcrypt@
xspasswd_LDFLAGS = @ldcrypt@
xschpass_LDFLAGS = @ldcrypt@
LDADD = libxs.a				# default for all *_PROGRAMS

EXTRA_DIST = cgi.h config.h confpatch.h confuser.h convert.h \
	digcalc.h err.h extra.h htconfig.h httpd.h local.h methods.h \
	mygetopt.h mystring.h \
	path.h procname.h setenv.h ssi.h xscounter.h xscrypt.h

EXTRA_DIST += digcalc.c
