package Embed::Persistent;
#persistent.pl

use strict;
use vars '%Cache';
use Symbol qw(delete_package);

sub valid_package_name {
	my($string) = @_;
	$string =~ s/([^A-Za-z0-9\/])/sprintf("_%2x",unpack("C",$1))/eg;
	# second pass only for words starting with a digit
	$string =~ s|/(\d)|sprintf("/_%2x",unpack("C",$1))|eg;

	# Dress it up as a real package name
	$string =~ s|/|::|g;
	return "Embed" . $string;
}

sub eval_file {
	my $filename = join(' ', @_);
	my $package = valid_package_name($filename);
	my $mtime = -M $filename;
	if(defined $Cache{$package}{mtime}
	   &&
	   $Cache{$package}{mtime} <= $mtime)
	{
	   # we have compiled this subroutine already,
	   # it has not been updated on disk, nothing left to do
	   print STDOUT "already compiled $package->handler\n";
	}
	else {
	   local *FH;
	   open FH, $filename or die "open '$filename' $!";
	   local($/) = undef;
	   my $sub = <FH>;
	   close FH;

	   #wrap the code into a subroutine inside our unique package
	   my $eval = qq{package $package; sub handler { $sub; }};
	   {
	   # hide our variables within this block
	   my($filename,$mtime,$package,$sub);
	   eval $eval;
	   }
	   die $@ if $@;
	}

	eval {$package->handler;};
	die $@ if $@;

	elete_package($package);

	#take a look if you want
	#print Devel::Symdump->rnew($package)->as_string, $/;
}

1;
