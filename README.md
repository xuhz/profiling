# profiling

I have been using Dtrace on Solaris for a long time to do kernel profiling. When I start to do kernel profiling on Linux using
stap and perf, I realize some post-processing scripts which used to handle the Dtrace output can be used to handle the stap and
perf output too with very trivial change. I log those scripts her for my own referrence, and I hope it may all benifit others
who are doing kernel profiling using stap and/or perf on Linux.

Kernel profiling can be timer interrupt based or HW counter overflow interrupt based. The HW counter can be cpu cycles, L1/2/3,
or TLB cache hit/miss, or others(the kinds of HW counters supported are platform dependent). When the interrupt happens, some info
are recorded. The most typical ones are the PC and the stack, with enough of which we can know the percentage of contributation of each
functions to the interrupt. Another typical info recorded can be VA/PA, with which we can profile the memory space behavior, for
example, on 4k pages access in one numa node, how many TLB miss we have? or, how many memory accesses are going to 4k/2M/1G pages?
Those info would be very useful to decide how large pages can be used.

The output of the profiling is a collect of kernel stacks.

## Examples
Here are the examples that how stap and perf are doing kernel profiling with cpu cycles as trigger event.

### stap:
```
global s;
global usermode = 0;

probe perf.hw.cpu_cycles!, timer_profile {
	bt = user_mode();
	if (!bt)
		s[backtrace()] <<< 1;
}

probe end {
	foreach (i in s+) {
		printf("!\n");
		print_stack(i);
		printf("\t%d\n", @count(s[i]));
	}
	printf("!\n");
}

$sudo stap -DMAXMAPENTRIES=102400 -DMAXACTION=2048000 -DMAXSKIPPED=5000 stap.kp --all-modules --ldd -c "sleep 30" --vp 00001 >kp.out
```

One output stack looks like,

```
   ! 
 0xffffffff814cde75 : net_rx_action+0x105/0x2b0 [kernel]
 0xffffffff81066247 : __do_softirq+0xd7/0x240 [kernel]
 0xffffffff815a1ddc : call_softirq+0x1c/0x30 [kernel]
 0xffffffff810174b5 : do_softirq+0x65/0xa0 [kernel]
 0xffffffff8106602d : irq_exit+0xbd/0xe0 [kernel
 0xffffffff815a2a26 : do_IRQ+0x66/0xe0 [kernel]
 0xffffffff815983ad : ret_from_intr+0x0/0x15 [kernel]
        1
```
where,
'!' is the separator of the stacks, and '1' is the number of times this stack appears in the whole profiling.

### perf

```
root>perf record -a -g -F 497 sleep 30
root>perf script |./perfconvert.pl > kp.out
```

One output stack looks like,

```
 !
ffffffff81039e37 : smp_call_function_single_interrupt+ffffffff81039e37
ffffffff815a189d : call_function_single_interrupt+ffffffff815a189d
ffffffff814745f0 : cpuidle_enter_tk+ffffffff814745f0
ffffffff81473ff7 : cpuidle_enter_state+ffffffff81473ff7
ffffffff8147483a : cpuidle_idle_call+ffffffff8147483a
ffffffff8101dc5f : cpu_idle+ffffffff8101dc5f
ffffffff8158d511 : start_secondary+ffffffff8158d511
  3
```

The stack is a little bit different to that the previous stap one. The 'offset'  is actually the addr of the instruction. Maybe I should consult the /proc/kallsyms and then get the real offset.

By default, the HW counter used by perf is cpu cycles. With this HW counter as the interrupt trigger, the profile will not contain the 'idle' stack since when cpu will go to power saving mode when it is idle, where the cpu does not burn cycles. The cpu will exit the power saving mode when there is a hardware interrupt or a xcall targeting this cpu happens. The above stack shoes there is a xcall arrived and it wakes up the idle cpu. Note, these kinds of stacks only count cycles consumed by xcall or interrupt, but not the percentage of idle(which reported by vmstat/mpstat). In order to also count idle stacks, the 'cpu-clock' SW event should be used instead as the perf trigger event, like following,

```
root>perf record -a -g -F 497 -e "cpu-clock" sleep 30
```

The perf-report is not that straightforward, especially it doesn't show inclusive directly, which is more informative than exclusive in many cases.

There are some examples showing the use cases at the begining of the post-kp.pl file.
