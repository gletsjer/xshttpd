#!/usr/bin/env perl

# agentstats
#
# Display user statistic from CLF access log
# (c) July 2005, Ed Schouten

use strict;

my ($os, $browser, $total, $string);
my %hits = ();

# Try to open our logfile
if (open ('httpdlog', shift))
{
	my ($logline, $agent);

	do
	{
		# Get a single logfile entry
		$logline = <httpdlog>;

		# Get the user agent from the log entry
		if ($logline && $logline =~ /\" \"(.*?)\"$/)
		{
			$agent = $1;

			# Update the grand total
			$total++;

			($os, $browser) = '';

			# Step one - get the operating system
			if ($agent =~ /([a-zA-Z]*BSD)/)
			{
				$os = "$1";
			}
			elsif ($agent =~ /Linux/)
			{
				$os = 'Linux';
			}
			elsif (($agent =~ /Mac OS X/) ||
				($agent =~ / MSIE .* Mac_PowerPC/))
			{
				$os = 'Mac OS X';
			}
			elsif ($agent =~ /Mac OS/)
			{
				$os = 'Mac OS';
			}
			elsif ($agent =~ /SunOS/)
			{
				$os = 'Solaris';
			}
			# Windows at the bottom - a lot of spoofers
			elsif ($agent =~ /Windows/)
			{
				$os = 'Windows';
			}

			# Step two - get the browser
			if ($agent =~ / Arachmo/)
			{
				$browser = 'Bot: Arachmo Search';
			}
			elsif ($agent =~ / Ask Jeeves/)
			{
				$browser = 'Bot: Ask Jeeves Search';
			}
			elsif ($agent =~ /BigCliqueBOT\//)
			{
				$browser = 'Bot: BigClique Search';
			}
			elsif ($agent =~ / BorderManager /)
			{
				$browser = 'Proxy: Novell BorderManager';
			}
			elsif ($agent =~ /^Convera(MultiMedia)?Crawler\//)
			{
				$browser = 'Bot: Convera Crawler';
			}
			elsif ($agent =~ / Camino\//)
			{
				$browser = 'Mozilla Camino';
			}
			elsif ($agent =~ / Cerberian Drtrs /)
			{
				$browser = 'Bot: Blue Coat Content Control';
			}
			elsif ($agent =~ /^curl\//)
			{
				$browser = 'Curl';
			}
			elsif ($agent =~ /^Dillo\//)
			{
				$browser = 'Dillo';
			}
			elsif ($agent =~ /DomainsDB\.net/)
			{
				$browser = 'Bot: DomainsDB.net Crawler';
			}
			elsif ($agent =~ /^ELinks\//)
			{
				$browser = 'ELinks';
			}
			elsif ($agent =~ /^fetch /)
			{
				$browser = 'Fetch';
			}
			elsif ($agent =~ / Firefox\//)
			{
				$browser = 'Mozilla Firefox';
			}
			elsif ($agent =~ / FrontPage /)
			{
				$browser = 'Microsoft FrontPage';
				$os = 'Windows';
			}
			elsif ($agent =~ /Google(bot(\-Image)?)?\//)
			{
				$browser = 'Bot: Google Search';
			}
			elsif ($agent =~ /INGRID\//)
			{
				$browser = 'Bot: Ilse Search';
			}
			elsif ($agent =~ /^Jigsaw\//)
			{
				$browser = 'Bot: W3C CSS Validator';
			}
			elsif ($agent =~ / Konqueror\//)
			{
				$browser = 'Konqueror';
			}
			elsif ($agent =~ /^lftp\//)
			{
				$browser = 'Lftp';
			}
			elsif ($agent =~ /^Links\//)
			{
				$browser = 'Links';
			}
			elsif ($agent =~ / Lotus\-Notes\//)
			{
				$browser = 'Lotus Notes';
			}
			elsif ($agent =~ /^Lynx\//)
			{
				$browser = 'Lynx';
			}
			elsif ($agent =~ /^msnbot\//)
			{
				$browser = 'Bot: MSN Search';
			}
			elsif ($agent =~ / Netcraft Web Server Survey/)
			{
				$browser = 'Bot: Netcraft Web Server Survey';
			}
			elsif ($agent =~ / Netscape/)
			{
				$browser = 'Netscape Navigator';
			}
			elsif ($agent =~ /Opera/)
			{
				$browser = 'Opera';
			}
			elsif ($agent =~ /^psbot\//)
			{
				$browser = 'Bot: PicSearch';
			}
			elsif ($agent =~ / Safari\//)
			{
				$browser = 'Safari';
			}
			elsif ($agent =~ / Thunderbird\//)
			{
				$browser = 'Mozilla Thunderbird';
			}
			elsif ($agent =~ /^W3C_Validator\//)
			{
				$browser = 'Bot: W3C HTML Validator';
			}
			elsif ($agent =~ / Yahoo! Slurp;/)
			{
				$browser = 'Bot: Yahoo Search';
			}
			elsif ($agent =~ / Vagabondo\//)
			{
				$browser = 'Bot: Kobala Search';
			}
			elsif ($agent =~ /^w3m\//)
			{
				$browser = 'W3m';
			}
			elsif ($agent =~ /^Wget\//)
			{
				$browser = 'Wget';
			}
			elsif ($agent =~ /ZyBorg\//)
			{
				$browser = 'Bot: WiseNut Search';
			}
			# Mozilla almost at the bottom - a lot of clones
			elsif ($agent =~ / Gecko\/[0-9]+/)
			{
				$browser = 'Mozilla Suite';
			}
			# MSIE at the bottom - a lot of spoofers
			elsif ($agent =~ / MSIE /)
			{
				$browser = 'Internet Explorer';
			}
			
			$string = ($browser ? $browser : 'Unknown browser');
			$string .= " - $os" if ($os);

			$hits{$string}++;

			# XXX: Debugging unknown agents
			#printf ("Unknown browser: %s\n", $agent)
			#	unless ($browser || $agent eq "UNKNOWN");
		}
	}
	while ($logline);

	close ('httpdlog');
}

# Display the operating system statistics
print " HITS \%HITS BROWSER\n";
for my $i (sort {$hits{$b} <=> $hits{$a}} keys %hits)
{
	printf "%5d %5.1lf %s\n",
		$hits{$i},
		($hits{$i} * 100) / $total,
		$i;
}
printf "%5d       total\n", $total;
