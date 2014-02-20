bin_PROGRAMS = httpd xspasswd clearxs readxs xsindex httpdc
phexec_PROGRAMS = imagemap error gfxcount xschpass
noinst_PROGRAMS = reformatxs xscat
noinst_LIBRARIES = libxs.a

httpd_SOURCES = httpd.c authenticate.c cgi.c cloader.c convert.c fcgi.c \
	methods.c modules.c path.c pcre.c ssi.c ssl.c xsfiles.c
httpd_CPPFLAGS = @httpd_cppflags@ -DBUILD_HTTPD
httpd_CFLAGS = @httpd_cflags@ @db_cflags@
httpd_LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib/httpd/module
httpd_LDADD = $(LDADD) @httpd_ldadd@ @db_ldadd@

libxs_a_SOURCES = decode.c hash.c extra.c path.c xscrypt.c
libxs_a_CFLAGS = -fPIC

httpdc_CPPFLAGS = -DBINDIR=\"$(bindir)\"

# default for all *_PROGRAMS
LIBS += libxs.a ../libcompat/libcompat.a
DEFAULT_INCLUDES = -I$(top_builddir)

EXTRA_DIST = alternative.h authenticate.h cgi.h cloader.h config.h \
	constants.h compiler.h convert.h decode.h extra.h fcgi.h fcgi_api.h \
	hash.h htconfig.h httpd.h httypes.h malloc.h methods.h modules.h \
	path.h pcre.h ssi.h ssl.h xsfiles.h xscounter.h xscrypt.h

include $(srcdir)/Modules.am

$(PROGRAMS): $(LIBS)

cscope:
	@cscope -bqv
