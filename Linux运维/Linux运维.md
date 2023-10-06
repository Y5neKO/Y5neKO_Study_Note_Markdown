# Linux运维

## Docker

### 介绍

Linux 发展出了另一种虚拟化技术：Linux 容器（Linux Containers，缩写为 LXC）。

Linux 容器不是模拟一个完整的操作系统，而是对进程进行隔离。或者说，在正常进程的外面套了一个[保护层](https://opensource.com/article/18/1/history-low-level-container-runtimes)。对于容器里面的进程来说，它接触到的各种资源都是虚拟的，从而实现与底层系统的隔离。

由于容器是进程级别的，相比虚拟机有很多优势。

**①启动快：**容器里面的应用，直接就是底层系统的一个进程，而不是虚拟机内部的进程。所以，启动容器相当于启动本机的一个进程，而不是启动一个操作系统，速度就快很多。

**②资源占用少：**容器只占用需要的资源，不占用那些没有用到的资源；虚拟机由于是完整的操作系统，不可避免要占用所有资源。另外，多个容器可以共享资源，虚拟机都是独享资源。

**③体积小：**容器只要包含用到的组件即可，而虚拟机是整个操作系统的打包，所以容器文件比虚拟机文件要小很多。

总之，容器有点像轻量级的虚拟机，能够提供虚拟化的环境，但是成本开销小得多。

**Docker 属于 Linux 容器的一种封装，提供简单易用的容器使用接口。**它是目前最流行的 Linux 容器解决方案。

Docker 将应用程序与该程序的依赖，打包在一个文件里面。运行这个文件，就会生成一个虚拟容器。程序在这个虚拟容器里运行，就好像在真实的物理机上运行一样。有了 Docker，就不用担心环境问题。

总体来说，Docker 的接口相当简单，用户可以方便地创建和使用容器，把自己的应用放入容器。容器还可以进行版本管理、复制、分享、修改，就像管理普通的代码一样。

### 安装

### 常用命令

```sh
docker login		#登录docker账号以push镜像
docker pull 镜像名:标签		#拉取指定镜像，默认标签使用latest
docker push 镜像id		#推送指定镜像到docker hub
docker images		#查看docker镜像
docker images -a	#查看所有的docker镜像，包括虚悬镜像（none标签）
docker ps  			#列出正在运行的docker容器状态
docker run			#运行docker容器
docker run -it 镜像名/容器id 命令		#以交互模式运行指定容器并分配一个伪输入终端，不使用命令默认执行dockerfile中的CMD
			-d		#后台运行容器并返回容器id
			-p 宿主机端口:容器端口		#将宿主机的端口映射到容器的端口
			-P		#随机端口映射
			--network=bridge/host/none	#设置容器的网络模式
			--privileged		#以特权模式运行容器
docker exec			#在运行的容器中执行命令
docker exec -it 容器id 命令		#在运行的容器中执行命令并以交互模式分配一个伪输入终端
docker stop 容器id		#停止指定的容器
docker commit 容器id 镜像名:标签		#保存指定的容器并命名为镜像名:标签
docker save -o 保存文件名 镜像名/容器id		#导出完整镜像
docker tag 镜像名/容器id 镜像名			#重命名镜像
```

### 常见问题

```sh
#启动脚本run.sh报错
#Standard_init_linux.go:190: exec user process caused "exec format error"
解决方法：启动脚本开头必须加：#!/bin/bash

#systemctl和service
```





## 杂项记录

### 查看Linux Deb包的依赖关系

```sh
Deb是debian linus的安装格式，跟red hat的rpm非常相似，最基本的安装命令是：dpkg -i file.deb。 
dpkg 是Debian Package的简写，是为Debian 专门开发的套件管理系统，方便软件的安装、更新及移除。所有源自Debian的Linux发行版都使用dpkg，例如Ubuntu等。

我这里用到的测试环境是Ubuntu，测试的包是：apache2_2.4.7-1ubuntu4.14_amd64.deb。

使用的命令：
dpkg --info apache2_2.4.7-1ubuntu4.14_amd64.deb | grep Depends
先获取包的信息，然后通过管道将“Depends”截取出来，就获得下图的结果：
得到的Depends就是依赖的包，如perl，apache-bin，apache2-data等
```

### vmware中ubuntu网卡失效

**1、先将network-manager服务关闭**

```bash
sudo service network-manager stop
```

**2、把network-manager的状态文件删除，后续重新运行network-manager服务后会自动生成**

```bash
sudo rm /var/lib/NetworkManager/NetworkManager.state
```

**3、编辑network-manager配置文件，将[ifupdown]中的managed=false改成true**

```bash
sudo gedit /etc/NetworkManager/NetworkManager.conf
```

**4、启动network-manager服务**

```bash
sudo service network-manager start
```
