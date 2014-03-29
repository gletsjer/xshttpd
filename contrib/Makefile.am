# INSTALL_DATA = $(INSTALL) -m 644 -b

contrib_DATA = caroot.pem SSL-Makefile powered-by-xs.gif
contrib_SCRIPTS = agentstats.pl persistent.pl logrotate.sh wwwstats.pl

EXTRA_DIST = $(contrib_DATA) $(contrib_SCRIPTS)

install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(htmldir)
