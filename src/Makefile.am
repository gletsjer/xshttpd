bin_PROGRAMS = httpd xspasswd clearxs readxs xsindex httpdc
cgi_PROGRAMS = xschpass imagemap error gfxcount
noinst_LIBRARIES = libxs.a

httpd_SOURCES = httpd.c cgi.c convert.c local.c methods.c ssi.c ssl.c
error_SOURCES = error.c local.c

libxs_a_SOURCES = decode.c extra.c path.c procname.c xscrypt.c
if MD5
httpd_SOURCES += digcalc.c 
endif
if PCRE
httpd_SOURCES += pcre.c 
endif
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

EXTRA_DIST = cgi.h config.h confpatch.h confuser.h convert.h decode.h \
	digcalc.h err.h extra.h htconfig.h httpd.h ldap.h local.h methods.h \
	mygetopt.h mystring.h \
	path.h pcre.h procname.h setenv.h ssi.h ssl.h xscounter.h xscrypt.h

EXTRA_DIST += digcalc.c ldap.c pcre.c
