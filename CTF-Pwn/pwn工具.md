# pwn工具用法



## gdb/pwndbg命令

### b breakpoint 下断点

**b \<函数名/文件名:函数名\>**：在指定函数处打断点

**b \<行号/文件名:行号\>**：在指定行数打断点，需要配合`gcc -g`选项

**b *(0x地址值)**：在该地址处的指令下断点

**b \<+偏移量/-偏移量\>**：在当前停住地方的偏移量位置下断点



### d delete 删除断点

**d \<断点ID\>**：删除断点

**d/delete**：删除所有断点



### l list 打印源代码

- 需要配合`gcc -g`选项

**l**：默认列出10行源代码

**l 行号**：列出行号附近10行源代码

**l 1,10**：列出1-10行源代码

**l 函数名**：列出函数开始10行源代码



### stack 查看栈

**stack 24**：查看24行栈内容



### 运行指令

**r**：运行或者重新运行

**n**：单步步过，不会进入函数内部

**s**：单步步入，进入函数内部

**c**：continue，在断点处停止之后，继续运行或到下一个断点



### i info 查看信息

**i break**：查看断点信息



### vmmap 查看内存分配情况



## pwntools命令

- `from pwn import *`												导入pwntools的所有模块
- `io = process("./test")`                                      读取本地进程
- `io = remote("192.168.1.1", 1234)`                 读取远程进程
- `io.recv()/recvline()`                                          读取回显内容
- `io.send()/sendline()`                                          发送数据
- `p32(0x01020304)/p64(0x01020304)`                   打包对应地址数据为32/64比特数据
- `io.interactive()`                                                  获取shell之后进入交互
- `shellcraft.sh()`                                                    生成sh模块的汇编代码
- `asm()`                                                                         对汇编代码进行简单汇编，生成机器码



## ROPgadget

- `ROPgadget --binary test.elf --string "/bin/sh"`			搜索指定字符串所在地址
- `ROPgadget --binary test.elf --only "pop|ret"`                查找形如pop xxx; ret;的汇编代码位置



## 踩坑记录

- `gcc -m32 test.c`报错，64位系统需要安装gcc-multilib拓展才能编译32位程序
