/* compile: 
 * gcc -fpic -pie -nostdlib sockpay.c -o sockpay
 */


long _write(long fd, char *buf, unsigned long len)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $1, %%rax\n"
			"syscall" : : "g"(fd), "g"(buf), "g"(len));
	asm("mov %%rax, %0" : "=r"(ret));
	return ret;
}

long _socket(long family, long type, long protocol)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $41, %%rax\n"
			"syscall" : : "g"(family), "g"(type), "g"(protocol));
	asm("mov %%rax, %0" : "=r"(ret));
	/* returns socket fd */
	return ret;
}

long _connect(int fd, char * addr, int addrlen)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $42, %%rax\n"
			"syscall" : : "g"(fd), "g"(addr), "g"(addrlen));
	asm("mov %%rax, %0" : "=r"(ret));
	/* returns socket fd */
	return ret;
}
void Exit(long status)
{
	__asm__ volatile("mov %0, %%rdi\n"
			"mov $60, %%rax\n"
			"syscall" : : "r"(status));
}

_start()
{
	/* AF_INET: 2 SOCK_STREAM: 1 */

	int i;
	long sfd = _socket(2, 1, 0);

/*
	not working...
	struct _in_addr{
		unsigned long s_addr;
	};
	struct _sockaddr_in{
		short sin_family;
		unsigned short sin_port;
		struct _in_addr sin_addr;
		char sin_zero[16];
	};

	struct _in_addr addr;
	struct _sockaddr_in sockin;
	addr.s_addr = 0x7f000001; // little endian
	sockin.sin_family = 2;
	sockin.sin_port = 0x115c;
	sockin.sin_addr = addr;
	for (i = 0; i < 16; i++)
	{
		sockin.sin_zero[i] = 0;
	}
*/
	if (sfd < 0)
	{
		_write(1, "no socket\n", 10);
		Exit(-1);
	}

	/* this works */
	char sockstruct[24] = {0x02, 0x00, 0x11, 0x5c, 0x7f, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	long ret = _connect(sfd,(char *)&sockstruct, 24);
	
	if (ret < 0)
	{
		_write(1, "not successful con\n", 19);
		Exit(ret);
	}
	_write(1, "bla\n", 4);

	ret = _write(sfd, "bla\n", 4);
	if (ret < 0)
	{
		_write(1, "not successful\n", 15);
		Exit(ret);
	}

	_write(1, "I am the payload who has hijacked your process!\n", 48);
	Exit(0);
}

