#!/usr/bin/perl -w

#
#Convert 'perf script' output to another kernel profiling output format that
#can feed to post-kp.pl
#
#Author: Brian.xu -- huazhuo.xu@gmail.com
#
while (<>) {
	chomp;
	if (/^.+[\s]+[0-9]+[\s]+\[[0-9]{3}\]/) {
		printf("\t1\n");
		printf(" !\n");
		next;
	}
	if (/^[\s]+([0-9A-Fa-f]+)[\s]+([\w]+)[\s]/) {
		$addr = $1;
		$func = $2;
		printf("%s : %s+%s/\n", $addr, $func, $addr);
	}
}
printf(" \t1\n");
printf(" !\n");
