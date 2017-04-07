#!/usr/bin/perl -w

#
#This is a post-processing script which is used to process the kernel profiling
#data collected by:
# dtrace on Solaris
# systemtap on Linux.
# perf on Linux
#
#The collected kernel profiling data is a collection of stacks.
#On Solaris, a stack has the format
# !                                                 
#              unix`disp_getwork
#              unix`swtch+0xad
#              genunix`cv_wait+0x60
#              mac`mac_rx_fanout_worker+0xb3
#              unix`thread_start+0x8
#                1
#On Linux, it has the format
#stap:
# ! 
# 0xffffffff814cde75 : net_rx_action+0x105/0x2b0 [kernel]
# 0xffffffff81066247 : __do_softirq+0xd7/0x240 [kernel]
# 0xffffffff815a1ddc : call_softirq+0x1c/0x30 [kernel]
# 0xffffffff810174b5 : do_softirq+0x65/0xa0 [kernel]
# 0xffffffff8106602d : irq_exit+0xbd/0xe0 [kernel]
# 0xffffffff815a2a26 : do_IRQ+0x66/0xe0 [kernel]
# 0xffffffff815983ad : ret_from_intr+0x0/0x15 [kernel]
#        1
#
#perf:
# !
#ffffffff81039e37 : smp_call_function_single_interrupt+ffffffff81039e37/
#ffffffff815a189d : call_function_single_interrupt+ffffffff815a189d/
#ffffffff814745f0 : cpuidle_enter_tk+ffffffff814745f0/
#ffffffff81473ff7 : cpuidle_enter_state+ffffffff81473ff7/
#ffffffff8147483a : cpuidle_idle_call+ffffffff8147483a/
#ffffffff8101dc5f : cpu_idle+ffffffff8101dc5f/
#ffffffff8158d511 : start_secondary+ffffffff8158d511/ 
#    1
#
#where, '!' is the separator of the stacks. '1' is the number of times this stack
#appears.
#
#the 'offset' is actually the addr. maybe I should check the start addr of the func
#in /proc/kallsym and get the offset.
#
#the perf input can be gotten by run,
#perf record -a -g -F 497 sleep 30
#perf script |./perfconvert.pl > perf.kpstk 
#
#by default the HW counters used by stap and perf is cpu cycles.
#if idle stacks are required to be shown up, this HW counter is not the one to use, because when cpu goes idle,
#it will enter power saving mode, where no cpu cycles are burned. In this case, a HW interrupt or a x-call will
#wake the cpu up.
#"cpu-clock" SW event is the good one instead. With this event specified, the percentage of the idle functions is
#consisitent to what is shown by mpstat/vmstat. The usr/sys percentage is also consistent. I prefer to use this
#event as following,
#perf record -a -g -e cpu-clock -F 497 sleep 30
#
#Examples:
#1. Show the 'inclusive' and 'exclusive' of kernel functions.
# #post-kp.pl file1.stk
#Function                         Inclusive              Exclusive
#cpu_idle                        71.66%(428413)           0.02%(143)
#cpuidle_idle_call               70.49%(421394)           0.02%(91)
#cpuidle_enter_state             70.46%(421216)           0.01%(82)
#cpuidle_enter_tk                70.44%(421134)           0.00%(18)
#cpuidle_wrap_enter              70.44%(421116)          68.49%(409474)
#start_secondary                 70.37%(420716)           0.00%(0)
#(usermode)                      15.06%(90041)           15.06%(90041)
#system_call_fastpath             6.63%(39651)            0.01%(40)
#__do_softirq                     5.18%(30988)            0.79%(4729)
#call_softirq                     5.18%(30973)            0.00%(0)
#do_softirq                       5.10%(30461)            0.01%(32)
#irq_exit                         4.82%(28799)            0.00%(0)
#sock_aio_read                    4.04%(24166)            0.04%(239)
#inet_recvmsg                     4.04%(24138)            0.02%(91)
#tcp_recvmsg                      4.03%(24086)            0.12%(720)
#...
#
#
#The output is sorted by 'inclusive'. If 'exclusive' sorting is desired, run instead,
# #post-kp.pl -m "bothe" file1.stk
# or
# #post-kp.pl -m "ex" file1.stk
# to show only the 'exclusive'
#
#'-n' can be used to show only the top 'n' rows.
#
#2. Show difference of 2 profilings.
# #post-kp.pl file1.stk file2.stk 
#Function			Inclusive1	Inclusive2	Diff
#system_call_fastpath             4.08%		 6.63%		 2.55%
#call_softirq                     3.52%		 5.18%		 1.66%
#__do_softirq                     3.52%		 5.18%		 1.66%
#do_softirq                       3.49%		 5.10%		 1.60%
#inet_recvmsg                     2.49%		 4.04%		 1.55%
#tcp_recvmsg                      2.48%		 4.03%		 1.54%
#sock_aio_read                    2.51%		 4.04%		 1.53%
#irq_exit                         3.31%		 4.82%		 1.50%
#do_aio_read                      2.46%		 3.96%		 1.50%
#...
#
#By default, on 'inclusive' is displayed. Sorted by 'inclusive'
#
#3. Show top 3 callers of funcA in file1.stk
# #post-kp.pl -C funcA -n 3 file1.stk
#
#-------------------Caller-----------------
#   tcp_transmit_skb                     1.10%(5631)
#   tcp_write_xmit                      
#-----------------------------------------
#   tcp_transmit_skb                     0.83%(4265)
#   tcp_send_ack                        
#-----------------------------------------
#
#The percentage is the 'inclusive' percentage.
#
#4. Show top 3 callers differentiated by call stacks of funcA in file1.stk
# #post-kp.pl -C funcA -n 3 -s 100 file1.stk
#
#-------------------Caller-----------------
#   tcp_transmit_skb                     0.51%(2615)
#   tcp_write_xmit                      
#   tcp_push_one                        
#   tcp_sendmsg                         
#   inet_sendmsg                        
#   sock_aio_write                      
#   do_aio_write                        
#   do_sync_write                       
#   vfs_write                           
#   sys_write                           
#   system_call_fastpath                
#-----------------------------------------
#   tcp_transmit_skb                     0.30%(1554)
#   tcp_write_xmit                      
#   __tcp_push_pending_frames           
#   tcp_push                            
#   tcp_sendmsg                         
#   inet_sendmsg                        
#   sock_aio_write                      
#   do_aio_write                        
#   do_sync_write                       
#   vfs_write                           
#   sys_write                           
#   system_call_fastpath                
#-----------------------------------------
#   tcp_transmit_skb                     0.30%(1547)
#   tcp_send_ack                        
#   __tcp_ack_snd_check                 
#   tcp_rcv_established                 
#   tcp_v4_do_rcv                       
#   tcp_prequeue_process                
#   tcp_recvmsg                         
#   inet_recvmsg                        
#   sock_aio_read                       
#   do_aio_read                         
#   do_sync_read                        
#   vfs_read                            
#   sys_read                            
#   system_call_fastpath                
#-----------------------------------------
#
#'-s' is used to specify the depth of the stacks.
#
#5. Show all of the callees of funcA in file1.stk
# #post-kp.pl -c tcp_transmit_skb file1.stk
#
#-------------------callee-----------------
#tcp_transmit_skb         1.93%(9897)  ex: 0.07%(356)
#-----------------------------------------
# --> ip_queue_xmit                        1.74%(8892)
# --> skb_clone                            0.05%(260)
# --> tcp_v4_send_check                    0.03%(168)
# --> tcp_established_options              0.02%(99)
# --> tcp_options_write                    0.02%(79)
# --> skb_push                             0.00%(24)
# --> __tcp_select_window                  0.00%(19)
#
#6. Show expensive instructions of funcA in file1.stk
# #post-kp.pl -f funcA file1.stk
#
#---------------non-coalesce function-----------------
#tcp_transmit_skb+0x42f   1.74%(8893)
#tcp_transmit_skb+0xa2   0.05%(260)
#tcp_transmit_skb+0x372   0.03%(171)
#tcp_transmit_skb+0xf4   0.02%(101)
#tcp_transmit_skb+0x2be   0.02%(81)
#...
#
#In this example, the most expensive instruction is actually a func call.
#crash> dis tcp_transmit_skb+0x42a -x 3
#0xffffffff8151f4da <tcp_transmit_skb+0x42a>:    mov    %r12,%rdi
#0xffffffff8151f4dd <tcp_transmit_skb+0x42d>:    callq  *(%rax)
#0xffffffff8151f4df <tcp_transmit_skb+0x42f>:    test   %eax,%eax
#
#on x86, the instruction AFTER the call is pushed on the stack.
#this '-f' option is useful to identify cache miss of a memory access.
#
#
#Author: Brian Xu -- huazhuo.xu@gmail.com. 
#

use Getopt::Std;

my %options=();
getopts("hc:C:f:m:n:s:", \%options);

my ($help,$summary,$mode,$cler,$clee,$ncoalesce,$depth,$count);
my ($total1,$total2);
my (%incl1,%incl2);
my (%excl1,%excl2);
my (%caller_callee1,%caller_callee2);
$summary = 1; #by default, display the summary;
$mode = "bothi";#by default, display both inclusive and exclusive, sort by inclusive;
$depth = 1;#used by the caller-callee.
$total1 = 0;
$total2 = 0;
my $diff = 0;
my (%incldiff,%excldiff);
my $os = `uname`;

$help = $options{h} if defined $options{h};
$summary = $options{s} if defined $options{s};
$mode = $options{m} if defined $options{m};
$cler = $options{c} if defined $options{c};
$clee = $options{C} if defined $options{C};
$ncoalesce = $options{f} if defined $options{f};
$count = $options{n} if defined $options{n};
$depth = $options{s} if defined $options{s};

if ($cler or $clee or $ncoalesce) {
	$summary = 0;
}
if ($ncoalesce and ($cler or $clee)) {
	printf("-f and [-Cc] are mutual exclusive!\n");
	exit(1);
}

if ($help or !@ARGV) {
	printf("Usage:\n");
	printf("  post-kp [-m bothi|bothe|in|ex][-c func][-C func][-f func][-n num]\n");
	printf("          [-s depth] file1.kp [file2.kp]\n");
	printf("Options:\n");
	printf("\t-h -- help\n");
	printf("\t-m -- display inclusive, exclusive or both(sort by inclusive or exclusive\n");
	printf("\t-c -- print inclusive of the functions the specified function called\n"); 
	printf("\t-C -- print inclusive of the functions that call the specified function\n"); 
	printf("\t-f -- print exclusive of the individual instructions of the specified function\n");
	printf("\t-s -- set depth of stack to display. default is 1\n");
	printf("\t-n -- print the top 'n' entries for options 'cCf'\n");
	exit;
}

sub scan_file {
	my $file = shift;
	my $inclref = shift;
	my $exclref = shift;
	my $caller_callee_ref = shift;
	my $totalref = shift;
	my $newstack = 0;
	my $index = 0;
	my ($func, $prefunc, $i, $tr);
	my (@thisline, @k, %fnc);
	my $os = `uname`;
	chomp($os);
	while (<$file>) {
		chomp;
		if (/!/) {
			if ($newstack > 0 and $index > 1)  {
				for($i=0; $i<$index-1; $i++) {
					$func = $thisline[$i];
					$func =~ s/^.*[: |`]//;
					$func =~ s/\/.*$//;
					
					if (!$ncoalesce) {
						#If in non-coalesce mode, that is, we 
						#want to show function level info, 
						#instead of instruction level info, then
						#remove the offset.
						$func =~ s/\+.*$//;
					}
					$fnc{$func}++;
					if ($i == 0) {
						$$exclref{$func} += $thisline[$index-1];
					} else { 
						$$exclref{$func} += 0;
						$func = $func."+".$prefunc;
					}
					$prefunc=$func;
				}
				$$totalref += $thisline[$index-1];
				@k = keys %fnc;
				foreach $tr(@k) {
					$$inclref{$tr} += $thisline[$index-1]*$fnc{$tr};
				}
				$$caller_callee_ref{$func} += $thisline[$index-1];
				#now delete
				foreach $tr(@k) {
					delete $fnc{$tr};
				}
				for ($i=0; $i<$index-1; $i++) {
					delete $thisline[$i];
					delete $k[$i];
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
}


my $infile;
open($infile, '<', $ARGV[0]) or die "Could not open file '$ARGV' $!";
&scan_file($infile, \%incl1, \%excl1, \%caller_callee1, \$total1);
close($infile);
if ($ARGV[1]) {
	open($infile, '<', $ARGV[1]) or die "Could not open file '$ARGV' $!";
	&scan_file($infile, \%incl2, \%excl2, \%caller_callee2, \$total2);
	close($infile);
	$diff = 1;
}

sub getdiff {
	my $hs1ref = shift;
	my $num1 = shift;
	my $hs2ref = shift;
	my $num2 = shift;
	my $diffref = shift;
	my (@hsk, $fn);
	@hsk = keys %$hs1ref;
 	foreach $fn(@hsk) {
		if (exists($$hs2ref{$fn})) {
			$$diffref{$fn} = (100*$$hs2ref{$fn}/$num2) - (100*$$hs1ref{$fn}/$num1);
		} else {
			$$diffref{$fn} = 0 - 100*$$hs1ref{$fn}/$num1;
		}
	}
	@hsk = keys %$hs2ref;
	foreach $fn(@hsk) {
		if (exists($$hs1ref{$fn})) {
			next;
		} else {
			$$diffref{$fn} = 100*$$hs2ref{$fn}/$num2;
		}
	}
}

if ($diff) {
	#in diff mode, we just display inclusive(by default) or exclusive.
	if(($mode eq "bothi") or ($mode eq "bothe")) {
		$mode = "in";
	}
	&getdiff(\%incl1, $total1, \%incl2, $total2, \%incldiff);
	&getdiff(\%excl1, $total1, \%excl2, $total2, \%excldiff);
}	
if ($summary) {
	my (@ov,$kout,$n);
	if ($mode eq "ex" and $diff) {
		printf("Function\t\t\tExclusive1\tExclusive2\tDiff\n");
		@ov= sort {$excldiff{$b}<=>$excldiff{$a} or $b cmp $a} keys %excldiff;
	} elsif ($mode eq "in" and $diff) {
		printf("Function\t\t\tInclusive1\tInclusive2\tDiff\n");
		@ov= sort {$incldiff{$b}<=>$incldiff{$a} or $b cmp $a} keys %incldiff;
	} elsif ($mode eq "bothi") {
		printf("Function\t\t\t Inclusive\t\tExclusive\n");
		@ov= sort {$incl1{$b}<=>$incl1{$a} or $b cmp $a} keys %incl1;
	} elsif ($mode eq "bothe") {
		printf("Function\t\t\t Inclusive\t\tExclusive\n");
		@ov= sort {$excl1{$b}<=>$excl1{$a} or $b cmp $a} keys %excl1;
	} elsif ($mode eq "ex") {
		printf("Function\t\t\tExclusive\n");
		@ov= sort {$excl1{$b}<=>$excl1{$a} or $b cmp $a} keys %excl1;
	} elsif ($mode eq "in") {
		printf("Function\t\t\tInclusive\n");
		@ov= sort {$incl1{$b}<=>$incl1{$a} or $b cmp $a} keys %incl1;
	} else {
		printf("mode must be bothi|bothe|in|ex!\n");
		exit(1);
	}
	$n=0;
	foreach $kout(@ov) {
		chomp($kout);
		if (!$count or ($count and $n++ < $count)) {
			if ($mode eq "in" and $diff) {
				printf("%-30s  %5.2f%%\t\t%5.2f%%\t\t%5.2f%%\n",
				    $kout,
				    exists($incl1{$kout}) ? 100*$incl1{$kout}/$total1:-100,
				    exists($incl2{$kout}) ? 100*$incl2{$kout}/$total2:-100,
				    $incldiff{$kout});
			} elsif ($mode eq "ex" and $diff) {
				printf("%-30s  %5.2f%%\t\t%5.2f%%\t\t%5.2f%%\n",
				    $kout,
				    exists($excl1{$kout}) ? 100*$excl1{$kout}/$total1:-100,
				    exists($excl2{$kout}) ? 100*$excl2{$kout}/$total2:-100,
				    $excldiff{$kout});
			} elsif ($mode eq "bothi" or $mode eq "bothe") {
				printf("%-30s  %5.2f%%(%d)\t\t%5.2f%%(%d)\n",
				    $kout,100*$incl1{$kout}/$total1,$incl1{$kout},
				    100*$excl1{$kout}/$total1,$excl1{$kout});
			} elsif ($mode eq "in") {
				printf("%-30s  %5.2f%%(%d)\n",
				    $kout,100*$incl1{$kout}/$total1,$incl1{$kout});
			} elsif ($mode eq "ex") {
				printf("%-30s  %5.2f%%(%d)\n",
				    $kout,100*$excl1{$kout}/$total1,$excl1{$kout});
			} else {
				printf("mode must be bothi|bothe|in|ex!\n");
				exit(1);
			}
		}
	}
}

sub get_callee {
	my $caller_callee_ref = shift;
	my $callees_ref = shift;
	my (@sk,$k,@cc,$i);
	my $thistk;
	@sk = keys %$caller_callee_ref;
	foreach $k(@sk) {
		chomp($k);
		@cc = split /\+/,$k;
		#skip the stacks that don't contain the func.
		if ($#cc == 0) {
			next;
		}
		#if the func is the top one in this stack, the func does not
		#have callee, skip it then.
		for ($i=0; $i<$#cc; $i++) {
			if ($cc[$i] eq $cler) {
				last;
			}
		}
		if ($i == $#cc) {
			next;
		}
		$thistk = $cc[$i]."+".$cc[$i+1];
		$$callees_ref{$thistk} += $$caller_callee_ref{$k};
	}

}

if ($cler) {#specify the caller, then display all of the callees.
	my (@sk,$k,@cc,$n,$i);
	my (%cleefn,$thistk);
	my (%cleefn1,%cleefn2,%cleediff);
	if (!exists($incl1{$cler}) or !exists($excl1{$cler})) {
		printf("%s not exist!\n", $cler);
		exit(1);
	}
	&get_callee(\%caller_callee1, \%cleefn1);
	if ($diff) {	
		&get_callee(\%caller_callee2, \%cleefn2);
		&getdiff(\%cleefn1, $total1, \%cleefn2, $total2, \%cleediff);
		printf("-------------------callee----------------File1\tFile2\tDiff\n");
		printf("%s    File1(%5.2f%% ex:%5.2f%%) File2(%5.2f%% ex:%5.2f%%)\n",
		    $cler,100*$incl1{$cler}/$total1,100*$excl1{$cler}/$total1,
		    100*$incl2{$cler}/$total2,100*$excl2{$cler}/$total2);
		@sk= sort {$cleediff{$b}<=>$cleediff{$a} or $b cmp $a} keys %cleediff;
	} else {
		printf("-------------------callee-----------------\n");
		printf("%-20s    %5.2f%%(%d)  ex:%5.2f%%(%d)\n",
		    $cler,100*$incl1{$cler}/$total1,$incl1{$cler},
		    100*$excl1{$cler}/$total1,$excl1{$cler});
		@sk= sort {$cleefn1{$b}<=>$cleefn1{$a} or $b cmp $a} keys %cleefn1;
	}
	printf("------------------------------------------\n");

	$n=0;
	foreach $k(@sk) {
		chomp($k);
		@cc = split /\+/,$k;
		if (!$count or ($count and $n++ < $count)) {
			if ($diff) {
				printf("  --> %-36s%5.2f%%  %5.2f%%  %5.2f%%\n",
				    $cc[1],
				    exists($cleefn1{$k})?100*$cleefn1{$k}/$total1:-100,
				    exists($cleefn2{$k})?100*$cleefn2{$k}/$total2:-100,
				    $cleediff{$k});
			} else {
				printf("  --> %-36s%5.2f%%(%d)\n",$cc[1],
				    100*$cleefn1{$k}/$total1,$cleefn1{$k});
			}
		}
	}
	if (!@sk) {
		printf("No callee!\n");
	}
}

sub get_caller {
	my $caller_callee_ref = shift;
	my $callers_ref = shift;
	my (@sk,$k,@cc,$i);
	my $maxdep;
	my $thistk;
	my $recursive;
	@sk = keys %$caller_callee_ref;
	foreach $k(@sk) {
		chomp($k);
		$recursive = 0;
		$maxdep = $depth;
		@cc = split /\+/,$k;
		if ($#cc == 0) {
			next;
		}
		for ($i=0; $i<=$#cc; $i++) {
			if ($cc[$i] eq $clee) {
				$recursive++;
			}
		}
		for ($i=0; $i<=$#cc; $i++) {
			if ($cc[$i] eq $clee) {
				last;
			}
		}
		if ($i > $#cc) {
			next;
		}
		if ($i > 0) {
			$thistk = $cc[$i];	
			while ($i > 0) {
				$thistk = $thistk."+".$cc[$i-1];
				$i--;
				$maxdep--;
				if ($maxdep == 0) {
					last;
				}
			}
		} else {
			#if the func is the bottom one in the stack, the func
			#does not have a caller.
			$thistk = $cc[0]."+bottom_of_stack!";
		}
		if ($recursive>1) {
			printf("Note: recursive!\n");
		}
		$$callers_ref{$thistk} += $$caller_callee_ref{$k} * $recursive;
	}
}

if ($clee) {#specify the callee, then print the callers
	my (@sk,$k,@cc,$n,$i);
	my (%clerfn1,%clerfn2,%clerdiff);
	if (!exists($incl1{$clee}) or !exists($excl1{$clee})) {
		printf("%s not exist!\n", $clee);
		exit(1);
	}
	&get_caller(\%caller_callee1, \%clerfn1);
	if ($diff) {	
		&get_caller(\%caller_callee2, \%clerfn2);
		&getdiff(\%clerfn1, $total1, \%clerfn2, $total2, \%clerdiff);
		printf("-------------------Caller-----------------File1\tFile2\tDiff\n");
		@sk= sort {$clerdiff{$b}<=>$clerdiff{$a} or $b cmp $a} keys %clerdiff;
	} else {
		printf("-------------------Caller-----------------\n");
		@sk= sort {$clerfn1{$b}<=>$clerfn1{$a} or $b cmp $a} keys %clerfn1;
	}
	$n=0;
	foreach $k(@sk) {
		chomp($k);
		@cc = split /\+/,$k;
		if (!$count or ($count and $n++ < $count)) {
			if ($diff) {
				printf("    %-36s%5.2f%%  %5.2f%%  %5.2f%%\n",
				    $cc[0],
				    exists($clerfn1{$k})?100*$clerfn1{$k}/$total1:-100,
				    exists($clerfn2{$k})?100*$clerfn2{$k}/$total2:-100,
				    $clerdiff{$k});
			} else {
				printf("    %-36s%5.2f%%(%d)\n",$cc[0],
				    100*$clerfn1{$k}/$total1,$clerfn1{$k});
			}
			for($i=1;$i<=$#cc;$i++) {
				printf("    %-36s\n",$cc[$i]);
			}
			printf("------------------------------------------\n");
		}
	}
}
if ($ncoalesce) {
	my (@sk,$k,@nc,$n);
	if ($diff) {
		printf("----\t\t\tFile1\tFile2\tDiff\n");
		@sk= sort {$incldiff{$b}<=>$incldiff{$a} or $b cmp $a} keys %incldiff;
	} else {
		printf("----------------non-coalesce function-----------------\n");
		@sk= sort {$incl1{$b}<=>$incl1{$a} or $b cmp $a} keys %incl1;
	}
	$n=0;
	foreach $k(@sk) {
		my $addr;
		chomp($k);
		@nc = split /\+/,$k;
		if (($ncoalesce eq $nc[0]) and
		    (!$count or ($count and $n++ < $count))) {
			if ($nc[1] =~ /^[fF]{4,8}/) {
				#this is the 'perf script' output. the number
				#behind the '+' is actually the addr instead of
				#the offset. We display the addr directly.
				$addr = $nc[1];
			} else {
				#this is the dtrace outpur or stap output. the
				#number behind the '+' is offset.
				$addr = $k;
			}
			if ($diff) {
				printf("%-20s  %5.2f%%  %5.2f%%  %5.2f%%\n",
				    $addr,
				    exists($incl1{$k})?100*$incl1{$k}/$total1:-100,
				    exists($incl2{$k})?100*$incl2{$k}/$total2:-100,
				    $incldiff{$k});
			} else {
				printf("%-20s  %5.2f%%(%d)\n",$addr,
				    100*$incl1{$k}/$total1,$incl1{$k});
			}
		}
	}
}
