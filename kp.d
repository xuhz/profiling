#!/usr/sbin/dtrace -qs

BEGIN {
 start = timestamp;
 finish = timestamp + 30 * 1000000000ull
}

tick-1sec
/timestamp >= finish/
{
	exit(0);
}


profile:::profile-479
/arg0/
{
    @a["!",stack(50)]  = count();
}

profile:::profile-479
/arg1/
{
    usermode++;
}

END {
 elapsed = timestamp - start;
 printf("%d.%09d seconds elapsed\n", elapsed/1000000000, elapsed%1000000000);
 printa(@a);
 printf("!\n");
 printf("(usermode)\n%d\n", usermode);
 printf("!\n");
}


