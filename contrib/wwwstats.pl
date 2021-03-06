#!/usr/bin/env perl

# wwwstats
#
# Display statistic from CLF access log with virtual hostnames
# (c) July 2005, Ed Schouten

use strict;

my %total = ();
my $logfile = shift;

sub sizetofriendly {
	my ($bytes) = @_;

	if ($bytes < 10**4)
	{
		return sprintf ("%dB", $bytes);
	}
	elsif ($bytes < 1024 * 10**4)
	{
		return sprintf ("%.1fK", $bytes / 1024.0);
	}
	elsif ($bytes < 1024 ** 2 * 10**4)
	{
		return sprintf ("%.1fM", $bytes / (1024.0 ** 2));
	}
	elsif ($bytes < 1024 ** 3 * 10**4)
	{
		return sprintf ("%.1fG", $bytes / (1024.0 ** 3));
	}
	else
	{
		return sprintf ("%.1fT", $bytes / (1024.0 ** 4));
	}
}

# Print a table look at the top
print "   TRAF \%TRAF    HITS \%HITS     AVG   \%AVG DOMAIN\n";

# Try to open our logfile
if (open ('httpdlog', "$logfile"))
{
	my $logline;
	my %domains = ();
	my %percent = ();

	do
	{
		# Get a single logfile entry
		$logline = <httpdlog>;

		if ($logline && $logline =~
			/^(.*?) .+ \[.+\] \".+ HTTP\/.+\" [0-9]{3} ([0-9]+) \"/)
		{
			# Log for the current domain
			$domains{$1}{'hits'}++;
			$domains{$1}{'size'} += $2;

			# Log for the grand total
			$total{'hits'}++;
			$total{'size'} += $2;
		}
	}
	while ($logline);

	close ('httpdlog');

	# Calculate the master average
	$total{'avg'} = $total{'size'} / $total{'hits'};

	for my $i (sort {$domains{$b}{'size'} <=> $domains{$a}{'size'}}
		keys %domains)
	{
		# Calculate the average size
		$domains{$i}{'avg'} =
			$domains{$i}{'size'} / $domains{$i}{'hits'};

		# Calculate the percentages for the current domain
		$percent{'hits'} =
			($domains{$i}{'hits'} * 100) / $total{'hits'};
		$percent{'size'} =
			($domains{$i}{'size'} * 100) / $total{'size'};
		$percent{'avg'} =
			($domains{$i}{'avg'} * 100) / $total{'avg'};

		printf "%7s %5.1lf %7d %5.1lf %7s %6.1lf %s\n",
			# Size
			&sizetofriendly ($domains{$i}{'size'}),
			$percent{'size'},
			# Hits
			$domains{$i}{'hits'},
			$percent{'hits'},
			# Average page site
			&sizetofriendly ($domains{$i}{'avg'}),
			$percent{'avg'},
			# Name
			$i;
	}
}

# Print the grand total
printf "%7s %13d %13s        total\n",
	# Size
	&sizetofriendly ($total{'size'}),
	# Hits
	$total{'hits'},
	# Average
	&sizetofriendly ($total{'avg'});
