noinst_LIBRARIES = libcompat.a
libcompat_a_SOURCES = dummy.c
libcompat_a_CFLAGS = -fPIC
libcompat_a_LIBADD = $(LIBOBJS)

CFLAGS += $(libcompat_a_CFLAGS)

DEFAULT_INCLUDES = -I$(top_builddir)
EXTRA_DIST = config.h
