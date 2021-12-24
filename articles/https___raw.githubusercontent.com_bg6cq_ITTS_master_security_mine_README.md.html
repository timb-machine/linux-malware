## [原创]一次挖矿入侵处理记录(2021.01.27)

本文原创：**中国科学技术大学 张焕杰**

修改时间：2021.01.27


## 一、突发的大量SSH扫描

2021.01.25 22:40，接到用户报告发现有来自校内7个IP的大量SSH扫描。同时，部署的蜜罐也发现有校内IP在进行扫描。

这些IP只有一个有校外访问权限对外发起了扫描，其他IP都是校内通信。第一时间禁止了这些IP通信。

由于校内服务器管理员和用户安全意识不强，大量使用弱密码，因此类似扫描是经常发生的，一般是服务器被入侵引起的。

2021.01.26 发现有一个IP在对外扫描，碰巧管理员是熟悉的老师，就提醒管理员关注。

2021.01.27 管理员提供了密码，登录后发现有若干台虚拟机均为简单密码，其中一台有连接校园网的网卡，黑客从这个网卡
入侵后，又入侵了其他虚拟机。

## 二、被入侵机器的查处情况

登录被入侵的虚拟机，执行`w、top、netstat`等命令有很大延迟，top看到CPU利用率较高，但显示的进程CPU利用率并不高。

执行`rpm -Va`没有看到明显被修改的系统关键文件，`netstat`等程序也未发现明显异常。

执行`ldd ldd /usr/bin/ls; ldd /usr/sbin/ss` 发现多了`/lib/libcurl.so.2.17.0 (0x00007f3718028000) 动态库`，
`find / -name libcurl.so.2.17.0` 找不到这个文件

执行`strace /bin/ls 2>t` 在t中可以看到
```
access("/etc/ld.so.preload", R_OK)      = 0
open("/etc/ld.so.preload", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=22, ...}) = 0
mmap(NULL, 22, PROT_READ|PROT_WRITE, MAP_PRIVATE, 3, 0) = 0x7f4f9c05c000
close(3)                                = 0
open("/lib/libcurl.so.2.17.0", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\20\34\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=27112, ...}) = 0
```

说明文件是存在的，但是`ls /lib`看不到，怀疑黑客使用/etc/ld.so.preload 加载了动态连接库后门来隐藏信息
(参考 https://www.freebuf.com/column/162604.html ，警惕利用Linux预加载型恶意动态链接库的后门)

strace配合tcpdump可以发现每次执行命令时，会访问www.fullskystar.top，由于机器无法访问外网，所以命令执行的很慢。

允许IP可以访问外网，看到与www.fullskystar.top 443端口有如下典型的挖矿通信流量：
```
发送：{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"CPU: 4C/4T Memory: 3GB XMRig: 6.6.0 Since:2021/1/25 18:42:4",
  "pass":"x","agent":"XMRig/6.6.0 (Linux x86_64) libuv/1.40.0 gcc/9.3.1","algo":["cn/1","cn/2","cn/r","cn/fast","cn/half",
  "cn/xao","cn/rto","cn/rwz","cn/zls","cn/double","cn/ccx","rx/0","rx/wow","rx/arq","rx/sfx","rx/keva","argon2/chukwa",
  "argon2/chukwav2","argon2/wrkz"]}}

接收：{"jsonrpc":"2.0","id":1,"error":null,"result":{"id":"ac694f3d69b506b8","job":{"blob":
  "0e0eb6a3c580067396fd31ac9a0b378b84a253e104e5404dae018f2290647ea0f784eabc4de88a00000081db68a2d810b369ca7cbb49f052530888278262d2b52db767c8cb1acc494775235b",
  "job_id":"KcXF8WaZx0","target":"ffff0000","algo":"rx/0","height":2283630,"seed_hash":"f1a94ed2953f45f464eb3948e105899933ea0780d3c70918ee78359f2f571985"},
  "extensions":["algo","nicehash","connect","tls","keepalive"],"status":"OK"}}
```

下载静态编译的busybox，继续处理
```
wget https://busybox.net/downloads/binaries/1.28.1-defconfig-multiarch/busybox-x86_64
mv busybox-x86_64 busybox
chmod +x busybox

[root@localhost ~]# ./busybox ls -al /etc/ld.so.preload
-rw-r--r--    1 root     root            22 Jan 25 17:38 /etc/ld.so.preload
[root@localhost ~]# ./busybox cat /etc/ld.so.preload
/lib/libcurl.so.2.17.0
 
[root@localhost ~]# ./busybox ls -al /lib/libcurl.so.2.17.0
-rwxr-xr-x    1 root     root         27112 Jan 25 17:38 /lib/libcurl.so.2.17.0

```

由此可以判定黑客通过 /etc/ld.so.preload 加载 libcurl.so.2.17.0 动态链接库，拦截对系统的访问，从而隐藏了有关信息，
导致top、netstat、ls等均无法看到黑客增加的文件和运行的程序。

## 三、被入侵机器的处理过程

1. 修改密码

使用 `passwd` 修改密码

2. 删除preload的动态库

执行以下命令，执行后ld.so.preload还在，但是libcurl.so.2.17.0被改了名字后不起作用
```
[root@localhost ~]# ./busybox sh
~ # ./busybox chattr -i /lib/libcurl.so.2.17.0; ./busybox mv /lib/libcurl.so.2.17.0 /lib/libcurl.so.2.17.0.old
~ # exit

# 执行以上命令后，退出重新登录，否则之前的bash是注入过libcurl.so的
# 下面的命令要等所有注入过libcurl.so.2.17.0的进程都退出后才有用，否则还会被改
# grep libcurl.so.2.17. /proc/*/maps 可以查看哪些进程被注入了
[root@localhost ~]# chattr -i /etc/ld.so.preload 
echo -n > /etc/ld.so.preload 
```

3. 清理恶意程序

执行以上命令后，top可以看到/usr/bin/bioset占了大量CPU，这是挖矿程序

`ls -al /usr/bin/bioset` 时间与被入侵的时间一致，同时修改的还有程序/usr/bin/kthreadd

Kill -9 这两个进程，系统正常。

同时发现 /root/.ssh/authorized_keys 中添加有黑客的公钥。

`chattr -i /usr/bin/kthreadd  /usr/bin/bioset /root/.ssh/authorized_keys` 后

以上4个文件备份后交给安全同行继续深入分析处理。

删除这4个文件，特别是authorized_keys，不然黑客还可以进来。

黑客还修改了/etc/resolv.conf，前面加了nameserver 223.6.6.6，但估计程序有bug，在resolv.conf后面填充了0，凑够了256字节，将这个文件也恢复。

至此处理完毕。

***
欢迎 [加入我们整理资料](https://github.com/bg6cq/ITTS)
