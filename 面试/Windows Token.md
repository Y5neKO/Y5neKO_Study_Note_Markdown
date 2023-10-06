# token简介

Token 是描述进程或者线程上下文安全的一个对象。安全上下文包含了与该进程或线程的账户、组、特权有关的描述信息。Token还包含一些其他信息，如会话id、完整性级别以及UAC虚拟化状态。

不同的⽤户登录计算机后， 都会⽣成⼀个 Access Token ，这个 Token 在⽤户创建进程或者线程时会被使⽤，不断的拷贝，这也就解释了A⽤户创建⼀个进程而该进程没有B⽤户的权限。一般用户双击一个进程都会拷贝explorer.exe 的 Access Token

Windows有两种类型的Token：

- Delegation token(授权令牌): 用于交互会话登录(例如本地用户直接登录、远程桌面登录)
- Impersonation token(模拟令牌): 用于非交互登录(利用net use访问共享文件夹)

两种token只在系统重启后清除

具有`Delegation token`的用户在注销后，该Token将变成`Impersonation token`，依旧有效



当前系统中的某个进程或者线程能访问什么样的系统资源，取决于当前令牌的权限

我们通过exp提权或者永恒之蓝等得到的权限即为System，假如我们利⽤mimikatz和hashdump不能获得 administrator⽤户的密码，那我们只能通过令牌窃取进⾏降权，获得administrator⽤户的shell， 从⽽以 administrator⽤户的身份启动某些服务 ( 某些服务只能通过administrator⽤户启动 )