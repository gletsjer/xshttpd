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
			elsif ($agent =~ /Win(dows|32)/)
			{
				$os = 'Windows';
			}

			# Step two - get the browser
 			if ($agent =~ /^AppleSyndication\//)
 			{
 				$browser = 'RSS: Apple Syndication (Safari)';
 				$os = 'Mac OS X';
 			}
			elsif ($agent =~ /^ia_archiver$/)
			{
				$browser = 'Bot: Alexa Web Search';
			}
			elsif ($agent =~ / Arachmo/)
			{
				$browser = 'Bot: Arachmo Search';
			}
			elsif ($agent =~ / Ask Jeeves/)
			{
				$browser = 'Bot: Ask Jeeves Search';
			}
			elsif ($agent =~ /^Avant Browser /)
			{
				$browser = 'Avant Browser';
				$os = 'Windows';
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
				$os = 'Mac OS X';
			}
			elsif ($agent =~ / Cerberian Drtrs /)
			{
				$browser = 'Bot: Blue Coat Content Control';
			}
			elsif ($agent =~ /^CoralWebPrx\//)
			{
				$browser = 'Coral Cache';
			}
			elsif ($agent =~ /^curl\//)
			{
				$browser = 'Curl';
			}
			elsif ($agent =~ /^DA /)
			{
				$browser = 'Download Accelerator';
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
			elsif ($agent =~ /UniversalFeedParser\//)
			{
				$browser = 'RSS: FeedParser';
			}
			elsif ($agent =~ /^fetch /)
			{
				$browser = 'Fetch';
			}
			elsif ($agent =~ /findlinks\//)
			{
				$browser = 'Bot: FindLinks';
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
			elsif ($agent =~ /^Gigabot\//)
			{
				$browser = 'Bot: Gigabot';
			}
			elsif ($agent =~ /Google(bot(\-Image)?)?\//)
			{
				$browser = 'Bot: Google Search';
			}
			elsif ($agent =~ /almaden\.ibm\.com/)
			{
				$browser = 'Bot: IBM Almaden WebFoundation';
			}
			elsif ($agent =~ /^ichiro\//)
			{
				$browser = 'Bot: Ichiro';
			}
			elsif ($agent =~ /INGRID\//)
			{
				$browser = 'Bot: Ilse Search';
			}
			elsif ($agent =~ /^Java\//)
			{
				$browser = 'Java';
			}
			elsif ($agent =~ /^Jigsaw\//)
			{
				$browser = 'Bot: W3C CSS Validator';
			}
			elsif ($agent =~ /^Jyxobot\//)
			{
				$browser = 'Bot: Jyxobot';
			}
			elsif ($agent =~ / Konqueror\//)
			{
				$browser = 'Konqueror';
			}
			elsif ($agent =~ /Larbin\//)
			{
				$browser = 'Bot: Larbin';
			}
			elsif ($agent =~ /^lftp\//)
			{
				$browser = 'Lftp';
			}
			elsif ($agent =~ /^Links[ \/]/)
			{
				$browser = 'Links';
			}
			elsif ($agent =~ / Lotus\-Notes\//)
			{
				$browser = 'Lotus Notes';
			}
			elsif ($agent =~ /^Lycos_Spider/)
			{
				$browser = 'Bot: Lycos Search';
			}
			elsif ($agent =~ /^Lynx\//)
			{
				$browser = 'Lynx';
			}
			elsif ($agent =~ /^HenryTheMiragoRobot /)
			{
				$browser = 'Bot: Mirago Search';
			}
			elsif ($agent =~ /^MJ12bot\//)
			{
				$browser = 'Bot: Majestic-12';
			}
			elsif ($agent =~ /^msnbot\//)
			{
				$browser = 'Bot: MSN Search';
			}
			elsif ($agent =~ /^MSProxy\//)
			{
				$browser = 'Microsoft Proxy';
			}
			elsif ($agent =~ / Netcraft Web Server Survey/)
			{
				$browser = 'Bot: Netcraft Web Server Survey';
			}
			elsif ($agent =~ /NetBSD-ftp\//)
			{
				$browser = 'ftp';
				$os = 'NetBSD';
			}
			elsif ($agent =~ / Netscape/)
			{
				$browser = 'Netscape Navigator';
			}
			elsif ($agent =~ /^NewsFire\//)
			{
				$browser = 'RSS: NewsFire';
				$os = 'Mac OS X';
			}
			elsif ($agent =~ /^Nutch/)
			{
				$browser = 'Bot: Apache Nutch';
			}
			elsif ($agent =~ /Opera/)
			{
				$browser = 'Opera';
			}
			elsif ($agent =~ /^PHP version tracker /)
			{
				$browser = 'Bot: PHP version tracker';
			}
			elsif ($agent =~ /^psbot\//)
			{
				$browser = 'Bot: PicSearch';
			}
			elsif ($agent =~ /^Prodiance Desktop Search Spider$/)
			{
				$browser = 'Bot: Prodiance Desktop Search';
			}
			elsif ($agent =~ /^RSS-SPIDER /)
			{
				$browser = 'Bot: RSS Spider';
			}
			elsif ($agent =~ / Safari\//)
			{
				$browser = 'Safari';
			}
			elsif ($agent =~ /^SurveyBot\//)
			{
				$browser = 'Bot: Whois Source Survey Bot';
			}
			elsif ($agent =~ /^SonyEricssonK300i\//)
			{
				$browser = 'Wap: Sony Ericsson K300i';
			}
			elsif ($agent =~ / Thunderbird\//)
			{
				$browser = 'Mozilla Thunderbird';
			}
			elsif ($agent =~ /TurnitinBot\//)
			{
				$browser = 'Bot: Turnitin';
			}
			elsif ($agent =~ /^W3C_Validator\//)
			{
				$browser = 'Bot: W3C HTML Validator';
			}
			elsif (($agent =~ / Yahoo! Slurp/) ||
			    ($agent =~ /^Yahoo-MM/))
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
			elsif ($agent =~ /^appie.*walhello/)
			{
				$browser = 'Bot: Walhello Search';
			}
			elsif ($agent =~ /^WebCopier /)
			{
				$browser = 'WebCopier';
			}
			elsif ($agent =~ /^Sqworm\//)
			{
				$browser = 'Bot: Websense Search';
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
			elsif (($agent =~ / MSIE /) ||
			    ($agent =~ /^Explorer\//))
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
