#include <stdio.h>
#include <unistd.h>

int print_hello(int n)
{
	printf("hello %d\n", n);
	return 0;
}

int main()
{
	int i;
	for (i = 0; i < 100; i++)
	{

		print_hello(i);
		sleep(1);
	}
	return 0;
}

