bin_PROGRAMS = httpd xspasswd clearxs readxs xsindex httpdc
cgi_PROGRAMS = xschpass imagemap error gfxcount

httpd_SOURCES = httpd.c local.c err.c procname.c extra.c ssi.c cgi.c \
	xscrypt.c path.c setenv.c methods.c convert.c
xspasswd_SOURCES = xspasswd.c err.c xscrypt.c extra.c
xschpass_SOURCES = xschpass.c xscrypt.c extra.c
imagemap_SOURCES = imagemap.c extra.c
clearxs_SOURCES = clearxs.c err.c extra.c
readxs_SOURCES = readxs.c err.c extra.c
error_SOURCES = error.c setenv.c local.c path.c
gfxcount_SOURCES = gfxcount.c err.c extra.c
httpdc_SOURCES = httpdc.c path.c err.c extra.c
xsindex_SOURCES = xsindex.c err.c extra.c

httpd_CFLAGS = @httpd_cflags@
httpd_LDADD = @LIBOBJS@
httpd_LDFLAGS = @httpd_ldflags@ @ldcrypt@
xspasswd_LDFLAGS = @ldcrypt@
xschpass_LDFLAGS = @ldcrypt@

EXTRA_DIST = cgi.h config.h confpatch.h confuser.h convert.h \
	err.h extra.h htconfig.h httpd.h local.h methods.h mygetopt.h mystring.h \
	path.h procname.h setenv.h ssi.h xscounter.h xscrypt.h
