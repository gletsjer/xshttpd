# Makefile for xs-httpd
# Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl)

# Some utilities for installing the programs

RM	= rm -f
CP	= cp -p
MKDIR	= mkdir -p
CHOWN	= chown
CHMOD	= chmod
#STRIP	= strip
STRIP	= true
SHELL	= /bin/sh

# What compiler do you have? Use an ANSI compatible one if you can!

CC	= gcc

# What flags do you need to give your compiler? The default below works
# for GCC. It optimizes the programs very well, and makes GCC gives ALL
# warnings. I absolutely HATE programs that do not compile without
# warnings. If you do not have GCC, no flags (an empty string after the
# = symbol) will suffice. If you know how to enable some optimization and
# more warning flags, turn them on!

#CFLAGS	= -O3 -Wall -pedantic -ansi
CFLAGS	= -g -Wall -pedantic -ansi

# Enable when using SSL
CFLAGS	+= -I/usr/local/include -I/usr/local/ssl/include

# If you have Linux, you need to uncomment the following line, otherwise
# your screen will be cluttered with warnings.

#CFLAGS	+= -D_BSD_SOURCE -D_GNU_SOURCE -D_POSIX_SOURCE

# What flags you you want to give to the linker? The default below
# strips the binary (removes any symbolname garbage). If you use
# FreeBSD (or any other operating system where crypt() is not in
# the C library), then add something like -lcrypt. If you're using
# SCO, you will to add -lintl because of strftime().

#LDFLAGS	= -s -lcrypt
LDFLAGS	=

# This is only linked with files that use crypt()
LD_CRYPT	= -lcrypt

# Enable only when using SSL
#LD_SSL	= -L/usr/local/lib -L /usr/local/ssl/lib -lcrypto -lssl

# Where should systemwide user-usable binaries be installed? This includes
# the WWW server itself, the controller (httpdc) and also the authentication
# password manager (xspasswd).

BINDIR	= /usr/local/bin

# Where should the manual pages be installed?

MANDIR	= /usr/local/man

# What should be used to "copy" the manual pages? If your system supports
# compressed or gzipped manual pages, use compress or gzip here. Do not forgot
# to fill in the appropriate extension. If your system accepts only plain
# manual pages, then fill in cat here, and use no extension.

MANPROG	= gzip
MANEXT	= .gz

# What is the root directory of the WWW server? This should be directory
# in which the subdirectories 'logs' and 'htdocs'will be placed.

HTTPDIR	= /usr/local/lib/httpd

# Location of the systemwide CGI binaries.

CGIDIR	= $(HTTPDIR)/cgi-bin

################################################
# No user configurable values after this line! #
################################################

all_with_text:	all
		@echo "Everything seems to have been compiled. The package"
		@echo "is now ready for installation. To install it, type"
		@echo "     make install      on a prompt."

all:		httpd xspasswd xschpass imagemap clearxs \
			readxs error gfxcount xsindex httpdc

.c.o:
		$(CC) $(CFLAGS) -c $<

httpd:		httpd.o local.o err.o procname.o extra.o ssi.o cgi.o \
			xscrypt.o path.o setenv.o methods.o convert.o
		$(CC) httpd.o local.o err.o procname.o extra.o ssi.o cgi.o \
			xscrypt.o path.o setenv.o methods.o convert.o \
			-o httpd $(LDFLAGS) $(LD_CRYPT) $(LD_SSL)
		$(STRIP) httpd

xspasswd:	xspasswd.o err.o xscrypt.o extra.o
		$(CC) xspasswd.o err.o xscrypt.o extra.o -o xspasswd \
			$(LDFLAGS) $(LD_CRYPT)
		$(STRIP) xspasswd

xschpass:	xschpass.o xscrypt.o extra.o
		$(CC) xschpass.o xscrypt.o extra.o -o xschpass $(LDFLAGS) $(LD_CRYPT)
		$(STRIP) xschpass

imagemap:	imagemap.o extra.o
		$(CC) imagemap.o extra.o -o imagemap $(LDFLAGS)
		$(STRIP) imagemap

clearxs:	clearxs.o err.o extra.o
		$(CC) clearxs.o err.o extra.o -o clearxs $(LDFLAGS)
		$(STRIP) clearxs

readxs:		readxs.o err.o extra.o
		$(CC) readxs.o err.o extra.o -o readxs $(LDFLAGS)
		$(STRIP) readxs

error:		error.o setenv.o local.o path.o
		$(CC) error.o setenv.o local.o path.o -o error $(LDFLAGS)
		$(STRIP) error

gfxcount:	gfxcount.o setenv.o extra.o
		$(CC) gfxcount.o setenv.o extra.o -o gfxcount $(LDFLAGS)
		$(STRIP) gfxcount

httpdc:		httpdc.o path.o err.o extra.o
		$(CC) httpdc.o path.o err.o extra.o -o httpdc $(LDFLAGS)
		$(STRIP) httpdc

xsindex:	xsindex.o err.o local.o extra.o
		$(CC) xsindex.o err.o extra.o -o xsindex $(LDFLAGS)
		$(STRIP) xsindex

install:	all
		-$(MKDIR) $(BINDIR) $(HTTPDIR) $(CGIDIR)
		-$(MKDIR) $(HTTPDIR)/logs $(HTTPDIR)/htdocs $(HTTPDIR)/icons
		-$(MKDIR) $(HTTPDIR)/gfxcount $(MANDIR)/man1
		if [ -f "$(CGIDIR)/xs-counter.data" ] ; \
		then \
			echo ">> xs-counter.data has moved in this version..." ; \
			echo ">> Moving it to $(HTTPDIR)/logs/xs-counter.data!" ; \
			mv $(CGIDIR)/xs-counter.data $(HTTPDIR)/logs/ ; \
		fi
		$(CP) httpd $(BINDIR)/
		$(CP) httpdc $(BINDIR)/
		$(CP) xspasswd $(BINDIR)/
		$(CP) clearxs $(BINDIR)/
		$(CP) readxs $(BINDIR)/
		$(CP) xsindex $(BINDIR)/
		$(CP) xschpass $(CGIDIR)/
		$(CP) imagemap $(CGIDIR)/
		$(CP) error $(CGIDIR)/
		$(CP) gfxcount $(CGIDIR)/
		for i in mime.types mime.index compress.methods script.methods ; \
		do \
			if [ -f "$(HTTPDIR)"/"$$i" ] ; \
			then \
				echo ">> $$i is already installed: skipped!" ; \
			else \
				$(CP) "$$i" $(HTTPDIR)/ ; \
			fi ; \
		done
		cd man ; for i in *.1 ; \
		do \
			$(MANPROG) < "$$i" > $(MANDIR)/man1/"$$i"$(MANEXT) ; \
		done
		$(CP) fonts/*.ppm $(HTTPDIR)/gfxcount/
		$(CP) icons/*.gif $(HTTPDIR)/icons/
		$(CHOWN) root $(CGIDIR)/xschpass
		$(CHMOD) u=srwx,g=rx,o=rx $(CGIDIR)/xschpass
		@echo "Finished installing!"
		@echo "You might need to adjust the ownership of the"
		@echo "files and subdirectories in $(HTTPDIR)"

clean:
		$(RM) httpd httpdc xspasswd xschpass imagemap clearxs error \
			readxs gfxcount xsindex *.core *.bin *.o *.s *.i core

###########################
# For Sven's personal use #
###########################

tar:		clean
		rm -f config.h config.h.old
		cp Makefile.original Makefile
		cd .. ; tar zcvf httpd.tar.gz httpd

copy-tar:	tar
		cp ../httpd.tar.gz $(HOME)/.html/xs-httpd/

copy-doc:
		cp doc/index.html $(HOME)/.html/xs-httpd/readme.html
		cp doc/ssi.html $(HOME)/.html/xs-httpd/
		cp doc/cgi.html $(HOME)/.html/xs-httpd/
