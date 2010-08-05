man1_MANS = httpd.1
man5_MANS = httpd.conf.5
dist_man1_MANS = clearxs.1 gfxcount.1 httpdc.1 \
	imagemap.1 readxs.1 xschpass.1 xsindex.1 xspasswd.1
dist_man5_MANS = xsauth.5 xsconf.5 xsredir.5 xsscripts.5
dist_man7_MANS = httpd_cgi.7 httpd_ssi.7
build_MANS = httpd.1.in httpd.conf.5.in

PREBUILD = .prebuild
BUILT_SOURCES = $(PREBUILD)
EXTRA_DIST = $(build_MANS)

do_subst = sed -e 's,[@]wwwdir[@],$(wwwdir),g' \
	-e 's,[@]configdir[@],$(configdir),g' \
	-e 's,[@]htmldir[@],$(htmldir),g' \
	-e 's,[@]SERVER_IDENT[@],$(SERVER_IDENT),g'

$(PREBUILD): $(build_MANS)
	@for m in $(build_MANS);\
	 do $(do_subst) $(srcdir)/$$m > $${m%%.in};\
	 done
	@touch $(PREBUILD)

clean-local:
	@rm -f $(man1_MANS) $(man5_MANS) $(man7_MANS) $(PREBUILD)
