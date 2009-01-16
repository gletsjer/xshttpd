bin_PROGRAMS = httpd xspasswd clearxs readxs xsindex httpdc
cgi_PROGRAMS = imagemap error gfxcount xschpass
noinst_PROGRAMS = reformatxs xscat
noinst_LIBRARIES = libxs.a libmod.a
AM_CPPFLAGS = -DHTTPD_ROOT=\"$(rootdir)\"

httpd_SOURCES = httpd.c authenticate.c cgi.c cloader.c convert.c fcgi.c \
	methods.c path.c pcre.c ssi.c ssl.c xsfiles.c
httpd_CFLAGS = $(httpd_cflags) -DBUILD_HTTPD
httpd_LDFLAGS = $(httpd_ldflags) $(libxs_ldflags) $(libmod_ldflags)
httpd_LDADD = $(LDADD) libmod.a

libxs_a_SOURCES = decode.c hash.c extra.c path.c xscrypt.c
libxs_a_CFLAGS = $(libxs_cflags)

libmod_a_SOURCES =
nodist_libmod_a_SOURCES = modules.c
libmod_a_CFLAGS = $(libmod_cflags)
if MOD_PERL
libmod_a_SOURCES += mod_perl.c
endif
if MOD_PYTHON
libmod_a_SOURCES += mod_python.c
endif
if MOD_RUBY
libmod_a_SOURCES += mod_ruby.c
endif
if MOD_LDAP
libmod_a_SOURCES += mod_ldap.c
endif

httpdc_CPPFLAGS = $(AM_CPPFLAGS) -DBINDIR=\"$(bindir)\"

# default for all *_PROGRAMS
LDADD = libxs.a ../libcompat/libcompat.a $(libxs_ldflags)
DEFAULT_INCLUDES = -I$(top_builddir)

EXTRA_DIST = alternative.h authenticate.h cgi.h cloader.h config.h \
	constants.h compiler.h convert.h decode.h extra.h fcgi.h fcgi_api.h \
	hash.h htconfig.h httpd.h malloc.h methods.h modules.h \
	path.h pcre.h ssi.h ssl.h xsfiles.h xscounter.h xscrypt.h

cscope:
	@cscope -bqv
