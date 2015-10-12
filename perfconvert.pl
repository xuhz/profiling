#!/usr/bin/perl -w

#
#Convert 'perf script' output to another kernel profiling output format that
#can feed to post-kp.pl
#
#this new version can aggregate the indetical stack. the perf profiling output doesn't aggregate the identical stacks,
#so the output may be very huge, especially on systems with a lot of cpus. with this new version, the size of the file
#which feeds to post-kp.pl is dramatically reduced.
#
#Author: Brian.xu -- huazhuo.xu@gmail.com
#
my $newstack = 0;
my $index = 0;
my @thisline;
my ($stk, $stkline, %astk);
while (<>) {
	chomp;
	if (/^.+[\s]+[0-9]+[\s]+\[[0-9]{3}\]/) {
		if ($newstack > 0 and $index > 1) {
			for($i=0;$i<$index;$i++) {
				if ($thisline[$i] =~ /^[\s]+([0-9A-Fa-f]+)[\s]+([\w]+)[\s]/) {
					$addr = $1;
					$func = $2;
					$stkline = $addr." : ".$func."+".$addr."/\n";
					if ($i == 0) {
						$stk = $stkline;
					} else {
						$stk = $stk.$stkline;
					}
				}
			}
			$astk{$stk} += 1;
			for($i=0;$i<$index;$i++) {
				delete $thisline[$i];
			}
			$index = 0;
		}
		$newstack++;
		next;
	}
	if ($newstack > 0) {
		$thisline[$index] = $_;
		$index++;
	}
}
#now count the last stack
for($i=0;$i<$index;$i++) {
	if ($thisline[$i] =~ /^[\s]+([0-9A-Fa-f]+)[\s]+([\w]+)[\s]/) {
		$addr = $1;
		$func = $2;
		$stkline = $addr." : ".$func."+".$addr."/\n";
		if ($i == 0) {
			$stk = $stkline;
		} else {
			$stk = $stk.$stkline;
		}
	}
}
$astk{$stk} += 1;

for (keys %astk) {
	print "!\n";
	print "$_";
	printf("\t%d\n", $astk{$_});
}
print "!\n";
