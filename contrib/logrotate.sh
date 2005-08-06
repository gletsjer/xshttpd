#!/bin/sh

# logrotate
#
# To be called from cron; calculates statistics and rotates logfile

# Change this to the correct location, e.g. /wwwsys/logs/access_log

LOGFILE=/usr/local/lib/httpd/logs/access_log

/usr/local/lib/httpd/wwwstats.pl ${LOGFILE}

# You should have something like this in your newsyslog.conf:
# /wwwsys/logs/access_log	644	7	*	*	JB

newsyslog -F ${LOGFILE}
