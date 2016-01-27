# x2cn_ctl 工具 

x2cn_ctl 工具是一个管理Postres-X2(原Postgres-XC)或Postgres-XL的管理工具。

## 安装方法

把src/x2cn_ctl.py 拷贝到/usr/local/bin目录下，改名为x2cn_ctl即可：

```
cp src/x2cn_ctl.py /usr/local/bin/x2cn_ctl
chmod 755 /usr/local/bin/x2cn_ctl
```

同时在/etc/目录下建x2cn_ctl.conf配置文件，可以从src/x2cn_ctl.conf文件为模板：

```
cp src/x2cn_ctl.conf /etc/.
```

## 配置方法

### 配置文件简介

示例配置文件类似如下：

```
[global]

# Postgres-X2的安装目录
pgx2_install_dir = /usr/local/pgx2
...
...

[coordinator]
#coordinator的postgresql.conf中的配置参数
listen_addresses = '*'
max_connections = 100
tcp_keepalives_idle = 10
...
...

[datanode]
#datanode的postgresql.conf中的配置参数
listen_addresses = '*'
max_connections = 200
tcp_keepalives_idle = 10
...
...

[host01]
hostname=postgres1
ip=192.168.10.20

have_gtm = 1
gtm_nodename = gtm
gtm_port = 6666
...
...

have_datanode = 1
datanode_nodename = datanode1
datanode_os_user = pgxc
...

[host02]
hostname=postgres2
ip=192.168.10.21

have_coordinator = 1
coordinator_nodename = coord2
...
...
```

配置文件/etc/x2cn_ctl.conf主要有以下几个section:

* global: 全局的一些配置项
* coordinator: coordinator的postgresql.conf中的配置参数
* datanode: datanode的postgresql.conf中的配置参数
* hostXX: 各台主机的配置项

### global 配置项


#### gloal 配置项简单

global 配置项的内容如下：

```
# Postgres-X2的安装目录
pgx2_install_dir = /usr/local/pgx2

# 初使化Postres-X2数据库时，创建出的默认数据库超级用户
g_pgx2_user = pg

# ip地址段
ip_prefix = 192.168.10

# 在ubuntu下，为.profile，而在Rhel和centos下为.bash_profile
profile_name = .bash_profile

#是否把数据库集群建在lxc中
use_lxc = 0

# 指定lxc的虚拟机所在的目录
lxc_path = /lxc_pgx2

#创建其它lxc虚拟机时使用的模板虚拟机
lxc_template = pgx2template
```

#### pgx2_install_dir


其中pgx2_install_dir表示Postgres-X2（或Postgres-XL）安装的路径，如果安装在/usr/local/pgxl目录下，则psql命令是在/usr/local/pgxl/bin/目录下：


```
[root@postgres1 /ssd02/xl_datanode01]
#ls -l /usr/local/pgxl/
total 16
drwxr-xr-x 2 root root 4096 Jan 27 13:34 bin
drwxr-xr-x 4 root root 4096 Jan 27 13:30 include
drwxr-xr-x 3 root root 4096 Jan 27 13:30 lib
drwxr-xr-x 4 root root 4096 Jan 27 13:34 share

[root@postgres1 /ssd02/xl_datanode01]
#ls -l /usr/local/pgxl/bin/psql
-rwxr-xr-x 1 root root 429589 Jan 27 13:30 /usr/local/pgxl/bin/psql
```

#### g_pgx2_user

g_pgx2_user指定初使化Postres-X2数据库时，创建出的第一个默认数据库超级用户的名称，刚创建完数据库集群后，需要此用户创建其它用户，第一次连接时要使用此用户连接数据库：


```
psql -p 5432 -Upg -d postgres

```

#### lxc的配置

是否把数据库集群建在LXC(Linux Container)，本工具支持把Postgres-X2创建在多个LXC的虚拟机中。

使用LXC主要为一些开发和测试工作快速提供环境。

本工具提供了自动创建这些LXC虚拟机的功能。

* use_lxc: 如果设置为1，则表示将把集群创建到一个LXC(Linux Container)中。
* lxc_path: 指定所有lxc虚拟机的将创建在此目录下。
* lxc_template: 创建其它lxc虚拟机时使用的模拟虚拟机，需要事先建好。


### coordinator配置小节

此小节的内容可以是postgresql.conf中任何合法的配置，这些配置项会被添加到所有coordinator的postgresql.conf文件中

注意：
* 不要指定“gtm_host”和“gtm_port”配置项，这些这两项就是后面指定gtm的配置自动生成的。
* Postgres-xl不支持min_pool_size，所以不要指定此配置。

下面是一个示例配置：

```
[coordinator]
#coordinator的postgresql.conf中的配置参数
listen_addresses = '*'
max_connections = 1000
tcp_keepalives_idle = 10
tcp_keepalives_interval = 20
tcp_keepalives_count = 3
shared_buffers = 512MB
max_wal_senders = 5
wal_keep_segments = 256
wal_level = hot_standby
hot_standby = off
logging_collector = on
track_activities = on
track_counts = on
track_io_timing = off
track_functions = pl
track_activity_query_size = 4096
autovacuum = on
# 注意Postgres-xl不支持min_pool_size
#min_pool_size = 10
max_pool_size = 1024
```


### datanode配置小节


此小节与coordinator小节类似，这里就不再赘述了。



### 各台主机的配置

各台主机的配置小节名称为 host01、host02、host03...

示例如下：

```
[host01]
hostname=postgres1
ip=192.168.10.20

have_gtm = 1
gtm_nodename = gtm
gtm_port = 6666
gtm_os_user = pgxc
gtm_os_uid = 800
gtm_pgdata = /dbdata/xl_gtmdata

#have_gtm_standby = 0
#gtm_standby_nodename = gtmstb
#gtm_standby_port = 7778
#gtm_standby_os_user = pgxl
#gtm_standby_os_uid = 800

have_coordinator = 1
coordinator_nodename = coord1
coordinator_os_user = pgxc
coordinator_os_uid = 800
coordinator_port = 5432
coordinator_pooler_port = 7778
coordinator_pgdata = /dbdata/xl_coord01

have_datanode = 1
datanode_nodename = datanode1
datanode_os_user = pgxc
datanode_os_uid = 800
datanode_port = 5433
datanode_pooler_port = 7779
datanode_pgdata = /dbdata/xl_datanode01
```

hostname配置项指定这台主机的hostname，ip配置项指定主机的IP地址。

have_gtm、have_gtm_standby、have_coordinator、have_datanode分别指定这台主机上是否要安装gtm、gtm standby、coordinator、datanode。

其中：
* gtm_nodename指定Postgres-X2中的nodename
* gtm_port指定gtm的端口
* gtm_os_user指定把gtm创建在哪个操作系统用户下。此操作系统用户本工具有命令自动创建。
* gtm_os_uid指定gtm所在的操作系统用户的uid。
* coordinator和datanode也有上面的类似的配置，这里就不赘述了。


## 使用方法

### 使用简介

带“--help”运行x2cn_ctl可以看到帮助：

```
#x2cn_ctl --help
x2cn_ctl v0.1 Author: osdba
usage: x2cn_ctl <command> [options]
    command can be one of the following:
      check_config    : add a lxc virtual machine.
      lxc_add         : add a lxc virtual machine.
      lxc_del         : delete a lxc virtual machine by name.
      lxc_add_all     : add all lxc virtual machine.
      lxc_del_all     : delete all lxc virtual machine.
      lxc_start_all   : start all lxc virtual machine.
      lxc_stop_all    : stop all lxc virtual machine.
      add_os_user     : add user to host.
      add_os_user_all : add every user to all host.
      del_os_user_all : delete every user to all host.
      initdb          : initdb in a datanode.
      initgtm         : initgtm.
      initgtm_standby : initgtm_standby.
      initgtm_proxy   : initgtm_proxy.
      initdb_all      : All pgx2 initdb.
      rm_pgdata_all   : delete all pgdata directory.
      start           : start pgx2.
      stop            : stop pgx2.
      status          : show status of pgx2.
      coord_reg_node  : Register node to coordinator.
      psql            : Using psql connect to coordinator or datanode.
      set             : Set database configuration in postgresql.conf
      get             : Get database configuration in postgresql.conf
```


从上面可以看到，此工具由各个子命令组成，在某一个子命令后加“--help”可以看到这个子命令的帮助，如下所示：

```
# x2cn_ctl add_os_user --help
=== x2cn_ctl V0.1 Author: osdba ===

Usage: x2cn_ctl add_os_user [options]


Options:
  -h, --help            show this help message and exit
  -l LOGLEVEL, --loglevel=LOGLEVEL
                        Specifies log level:  debug, info, warn, error,
                        critical, default is info
  -i IP, --ip=IP        The ip address of the lxc container
  -u UID, --uid=UID     The uid of the user
  -U USER, --user=USER  The username

```

一些子命令解释：

* lxc_add、lxc_del、lxc_add_all、lxc_del_all、lxc_start_all、lxc_stop_all这些命令可以创建、删除、启动、停止lxc虚拟机。
* add_os_user_all、del_os_user_all命令可以根据配置文件中的配置项，自动在所有主机上创建需要的所有操作系统用户
* initdb、initgtm、initgtm_standby、initgtm_proxy、initdb_all等命令通过数据库的initdb或initgtm命令初使化数据库实例。initdb_all命令把所有的数据库实例都初使化出来
* rm_pgdata_all命令所所有实例的PGDATA目录都删除掉，相当于数据库实例的数据全部删除掉。通常我们重新建数据库实例时，需要用此命令把之前的数据命令删除掉，以便重新创建。
* start、stop、status：分别对应启动、停止、查看数据库集群。
* coord_reg_node: 此命令用于刚建好集群后，调用“create node”命令把其它coordinator、datanode加到coordinator中。
* psql: 运行psql连接到某一个coordinator或datanode上。
* set: 设置所有coordinators或datanodes中的postgresql.conf参数。
* get: 获得postgresql.conf参数（目前还未实现）

### 第一次使用

在运行此命令之前，先按前面的描述配置好/etc/x2cn_ctl.conf文件。

当然一般我们还需要手工配置所机器上的/etc/sysctl.conf文件，把操作系统准备好，这里给一个sysctl.conf的示例：

```
kernel.shmmax=67683483648
kernel.shmall=4294967296
vm.min_free_kbytes=262144
kernel.sem=4096 524288 4096 1024
fs.file-max=6815744
net.ipv4.ip_local_port_range=9000 65500
net.core.rmem_default=262144
net.core.rmem_max=4194304
net.core.wmem_default=262144
net.core.wmem_max=1048576
fs.aio-max-nr=1048576
kernel.shmmni=4096
vm.nr_hugepages=16137
net.core.somaxconn = 1024
vm.dirty_background_ratio = 1
vm.dirty_ratio = 5
```


完成上面的步骤后，通常只需要以下步骤就可以建出一个Postgres-X2集群：

* x2cn_ctl add_os_user_all: 增加所有主机中需要的操作系统用户
* x2cn_ctl initdb_all: 初使化集群
* x2cn_ctl start: 启动集群
* x2cn_ctl coord_reg_node: 调用“create node”命令把其它coordinator、datanode加到coordinator中。

做完上面的步骤后，就可以连接此集群，在其中建表了：

```
#x2cn_ctl psql -c 1
=== x2cn_ctl V0.1 Author: osdba ===

psql (PGXL 9.2.0, based on PG 9.2.4 (Postgres-XL 9.2.0))
Type "help" for help.

postgres=# create table test01(id int primary key, note text) DISTRIBUTE BY HASH(id);
NOTICE:  CREATE TABLE / PRIMARY KEY will create implicit index "test01_pkey" for table "test01"
CREATE TABLE
postgres=#
```

上面使用了“x2cn_ctl psql -c 1”命令，其中“-c 1”表示连接到第一个coordinator中。




