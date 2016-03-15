#!/usr/bin/env python
# -*- coding:UTF-8

"""
Created on 2015-07-01

@author: tangcheng
"""
g_version = '0.1'
g_config_file = "/etc/x2cn_ctl.conf"

g_pgx2_install_dir = '/usr/local/pgx2'

g_lxc = {}

g_coord_conf_dict = {}
g_datanode_conf_dict = {}

# 下面的全局变量，内容只是示例，便于查看，真正的会在load_config()函数中重新初使化

g_ip_prefix = '10.0.3'
g_pgx2_user = 'pg'

# g_host_list中汇总了每台机器上有哪些操作系统用户，主要为了后面的在每台机器上加用户的操作
g_host_list = [
    {
        'hostame': 'dn01',
        'ip': '10.0.3.11',
        'os_user_list': {701: 'gtm', 702: 'gtm_standby'},
        'have_gtm': 0,
        'have_gtm_standby': 0,
        'have_gtm_proxy': 0,
        'have_coordinator': 1,
        'have_datanode': 1
    },
    {
        'hostame': 'dn02',
        'ip': '10.0.3.12',
        'os_user_list': {701: 'gtm', 702: 'gtm_standby'},
        'have_gtm': 0,
        'have_gtm_standby': 0,
        'have_gtm_proxy': 0,
        'have_coordinator': 1,
        'have_datanode': 1
    },
]

g_gtm = {
    'nodename': 'gtm',
    'port': 6666,
    'os_user': 'gtm',
    'os_uid': 701,
}

g_gtm_standby = {
    'nodename': 'gtmstb',
    'port': 6666,
    'os_user': 'gtm_standby',
    'os_uid': 702,
}

g_gtm_proxy = [
    {
        'nodename': 'gtmproxy01',
        'ip': '10.0.3.11',
        'port': 6666,
        'os_user': 'gtm_proxy',
        'os_uid': 703
    },
    {
        'nodename': 'gtmproxy02',
        'ip': '10.0.3.12',
        'port': 6666,
        'os_user': 'gtm_proxy',
        'os_uid': 703
    },
]

g_coord = [
    {
        'nodename': 'coord01',
        'ip': '10.0.3.11',
        'port': 6601,
        'os_user': 'gtm_proxy',
        'os_uid': 704
    },
    {
        'nodename': 'coord02',
        'ip': '10.0.3.12',
        'port': 6601,
        'pooler_port': 6801,
        'os_user': 'gtm_proxy',
        'os_uid': 704
    },
]

g_datanode = [
    {
        'nodename': 'dn01',
        'ip': '10.0.3.11',
        'port': 6701,
        'os_user': 'datanode',
        'os_uid': 704
    },
    {
        'nodename': 'dn02',
        'ip': '10.0.3.12',
        'port': 6701,
        'os_user': 'datanode',
        'os_uid': 704
    },
]


# 在ubuntu下叫‘.profile’，但在Rhel和centos下为‘.bash_profile’
g_profile_name = '.profile'
g_profile_pos_line = '''# ====== Add by x2cn_lxc ======'''

g_profile_append_content = ''
g_pg_hba_conf_append_content = ''

import os
import sys
import time
import tempfile
import subprocess

import logging
import logging.handlers

import ConfigParser
from optparse import OptionParser

logger = None


def init_logger(level):
    global logger

    def new_func(arg_func):
        return lambda x: arg_func(x.replace('\n', '\n    '))

    logger = logging.getLogger()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    # formatter = logging.Formatter('%(levelname)s %(message)s')
    stdout_handle = logging.StreamHandler()
    stdout_handle.setFormatter(formatter)
    logger.addHandler(stdout_handle)
    logger.setLevel(level)
    # 把原先的logger对象的函数info、debug等替换掉，当传进入的错误信息中有回车，会在每个回车前多加一些空格，以便打印的好看一些
    func_name_list = ['info', 'debug', 'warn', 'error', 'critical']
    for funcName in func_name_list:
        func = getattr(logger, funcName)
        setattr(logger, funcName, new_func(func))


def run_cmd(cmd):
    logger.debug("Run: %s" % cmd)
    os.system(cmd)


def run_cmd_result(cmd):
    global logger

    try:
        p = subprocess.Popen(cmd, shell=True, close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_msg = p.stdout.read()
        err_msg = p.stderr.read()
        err_code = p.wait()
        # logger.debug("Run: %s, return %s" % (cmd, out_msg))
        logger.debug("Run: %s" % cmd)
    except StandardError as e:
        raise e

    return err_code, err_msg, out_msg


def load_config():
    """
    从配置文件中读到配置，然后放到一些全局变量中
    :return:
    """
    global g_config_file
    global g_lxc

    global g_pgx2_install_dir
    global g_ip_prefix
    global g_pgx2_user
    global g_profile_name
    global g_profile_append_content
    global g_pg_hba_conf_append_content

    global g_host_list
    global g_gtm
    global g_gtm_standby
    global g_gtm_proxy
    global g_coord
    global g_datanode

    global g_coord_conf_dict
    global g_datanode_conf_dict

    del g_coord[:]
    del g_datanode[:]
    del g_gtm_proxy[:]
    del g_host_list[:]

    g_gtm.clear()
    g_gtm_standby.clear()

    config = ConfigParser.ConfigParser()
    config.read(g_config_file)

    g_pgx2_install_dir = config.get('global', 'pgx2_install_dir')

    use_lxc = config.getint('global', 'use_lxc')

    if use_lxc:
        g_lxc['path'] = config.get('global', 'lxc_path')
        g_lxc['template'] = config.get('global', 'lxc_template')

    g_ip_prefix = config.get('global', 'ip_prefix')
    g_pgx2_user = config.get('global', 'g_pgx2_user')

    g_pg_hba_conf_append_content = \
        "host    all             all             %s.0/24            trust\n" \
        "host    replication     %s        %s.0/24            trust\n" \
        % (g_ip_prefix, g_pgx2_user, g_ip_prefix)

    g_profile_append_content = \
        "export PATH=%s/bin:$PATH\n" \
        "export LD_LIBRARY_PATH=%s/lib:$LD_LIBRARY_PATH\n" \
        "export LANG=en_US.utf8\n" % (g_pgx2_install_dir, g_pgx2_install_dir)

    g_profile_name = config.get('global', 'profile_name')

    items = config.items('coordinator')
    for item in items:
        g_coord_conf_dict[item[0]] = item[1]

    items = config.items('datanode')
    for item in items:
        g_datanode_conf_dict[item[0]] = item[1]

    global_sections = ('global', 'coordinator', 'datanode')

    # 遍历配置文件中各台主机中的配置
    sections = config.sections()
    for section in sections:
        # 跳过全局配置的section，只扫描各台主机的配置
        if section in global_sections:
            continue
        hostname = config.get(section, 'hostname')
        ip = config.get(section, 'ip')
        host_info_dict = {
            'hostname': hostname,
            'ip': ip
        }

        g_host_list.append(host_info_dict)

        # 处理gtm,gtm_standby,gtm_proxy, coordinator,datanode的配置项
        #   配置项如“coordinator_nodename”这些都是由node_type（“coordinator”）和key（“nodename”）组合而成
        multi_item_node_type_list = ['gtm_proxy', 'coordinator', 'datanode']
        node_type_list = ['gtm', 'gtm_standby', 'gtm_proxy', 'coordinator', 'datanode']
        key_list = ['nodename', 'os_user', 'os_uid', 'port', 'pooler_port', 'pgdata']
        int_key_list = ['os_uid', 'port', 'pooler_port']  # 定义是整数的key
        node_gvar_dict = {'gtm': g_gtm, 'gtm_standby': g_gtm_standby, 'gtm_proxy': g_gtm_proxy,
                          'coordinator': g_coord, 'datanode': g_datanode}

        for node_type in node_type_list:
            have_key = 'have_%s' % node_type
            if config.has_option(section, have_key):
                host_info_dict[have_key] = config.getint(section, have_key)
            else:
                host_info_dict[have_key] = 0

            gvar = node_gvar_dict[node_type]

            if host_info_dict[have_key]:
                if node_type in multi_item_node_type_list:
                    # item_list存储某个类别(gtm_proxy,coordinator, datanode)的配置项，而每个配置项又是一个数组
                    #   数组表明这台机器上安装了这个类别的多个实例
                    #   item_list = {'nodename':['dn11', 'dn12',...], 'os_user': ['pg01', 'pg02',...], ...}
                    item_list = {}
                    for key in key_list:
                        # item_key为 'coordinator_nodename, coordinator_os_user'等类似的内容
                        item_key = '%s_%s' % (node_type, key)

                        # 如果配置项不存在，则跳过
                        if not config.has_option(section, item_key):
                            continue

                        # 每个配置项，可以由逗号分隔的多项，如datanode_nodename = dn11,dn12,dn13，
                        #   这表明一台机器上建了多个datanode
                        item_str = config.get(section, item_key)
                        str_list = item_str.strip().split(',')
                        if key in int_key_list:  # 数字类型
                            item_list[key] = [int(k) for k in str_list]
                        else:  # 字符串类型
                            item_list[key] = str_list

                    cnt = len(item_list['nodename'])
                    for key in item_list:
                        if len(item_list[key]) != cnt:
                            sys.stderr.write("Invalid config, section: %s, %s_%s not match %s_%s list!\n"
                                             % (section, node_type, key, node_type, 'nodename'))
                            sys.exit(1)

                    for i in range(cnt):
                        node = {
                            'hostname': hostname,
                            'ip': ip
                        }
                        for key in item_list:
                            node[key] = item_list[key][i]

                        gvar.append(node)
                else:
                    gvar['hostname'] = hostname
                    gvar['ip'] = ip
                    for key in key_list:
                        item_key = '%s_%s' % (node_type, key)
                        # 如果配置项不存在，则跳过
                        if not config.has_option(section, item_key):
                            continue

                        if key in int_key_list:
                            gvar[key] = config.getint(section, item_key)
                        else:
                            gvar[key] = config.get(section, item_key)

        # 后面会检查配置项，如果发现不正确的配置项，则设置为True
        invalid_config = False

        # 汇总每台机器上的操作系统用户到g_host_list中
        # 先生成一个字典，通过主机名hostname就能映射到g_host_list数组中第几项
        hostname2index = {}
        cnt = len(g_host_list)
        for i in range(cnt):
            hostname = g_host_list[i]['hostname']
            hostname2index[hostname] = i

        for node in (g_gtm, g_gtm_standby):
            if node:
                idx = hostname2index[node['hostname']]
                if 'os_user_list' not in g_host_list[idx]:
                    os_user_list = {}
                    g_host_list[idx]['os_user_list'] = os_user_list
                else:
                    os_user_list = g_host_list[idx]['os_user_list']

                os_uid = node['os_uid']
                os_user = node['os_user']
                if os_uid not in os_user_list:
                    os_user_list[os_uid] = os_user
                else:
                    if os_user != os_user_list[os_uid]:
                        sys.stderr.write("In host(%s), same uid(%s) but different user name(%s, %s)\n" %
                                         (node['hostname'], os_uid, os_user, os_user_list[os_uid]))
                        invalid_config = True

        for node_array in (g_gtm_proxy, g_coord, g_datanode):
            for node in node_array:
                idx = hostname2index[node['hostname']]
                if 'os_user_list' not in g_host_list[idx]:
                    os_user_list = {}
                    g_host_list[idx]['os_user_list'] = os_user_list
                else:
                    os_user_list = g_host_list[idx]['os_user_list']

                os_uid = node['os_uid']
                os_user = node['os_user']
                if os_uid not in os_user_list:
                    os_user_list[os_uid] = os_user
                else:
                    if os_user != os_user_list[os_uid]:
                        sys.stderr.write("In host(%s), same uid(%s) but different user name(%s, %s)\n" %
                                         (node['hostname'], os_uid, os_user, os_user_list[os_uid]))
                        invalid_config = True

        # 检查同一台机器上，不同的os_uid的用户名是否有相同的：
        for host_info_dict in g_host_list:
            user2uid = {}
            os_user_list = host_info_dict['os_user_list']
            for uid in os_user_list:
                os_user = os_user_list[uid]
                if os_user in user2uid:
                    sys.stderr.write("In host(%s), same user name (%s) but different uid(%s, %s)\n" %
                                     (host_info_dict['hostname'], os_user, uid, user2uid[os_user]))
                    invalid_config = True
                else:
                    user2uid[os_user] = uid

        # 检查有没有重复的nodename，对于postgres-X2要求唯一
        nodename2ip = {}
        for node_array in (g_gtm_proxy, g_coord, g_datanode):
            for node in node_array:
                nodename = node['nodename']
                if nodename in nodename2ip:
                    sys.stderr.write("Duplicate nodename: %s, the nodename must be unique!!!\n" % nodename)
                    invalid_config = True
                else:
                    nodename2ip[nodename] = node['ip']

        nodename = g_gtm['nodename']
        if nodename in nodename2ip:
            sys.stderr.write("Duplicate nodename: %s, the nodename must be unique!!!\n" % nodename)
            invalid_config = True

        if g_gtm_standby:
            nodename = g_gtm_standby['nodename']
            if nodename in nodename2ip:
                sys.stderr.write("Duplicate nodename: %s, the nodename must be unique!!!\n" % nodename)
                invalid_config = True

        # 检查同一台机器上是否配置了重复的端口
        node_array = [g_gtm]
        if g_gtm_standby:
            node_array.append(g_gtm_standby)
        node_array.extend(g_gtm_proxy)
        node_array.extend(g_coord)
        node_array.extend(g_datanode)

        # host_port_dict字典的key为ip地址，value又是一个以port为key的字典，其值类似为
        # {'192.168.0.201':{6666:['gtm', 'port'],
        #                   6543:['coord1', 'port']
        #                  }
        # }
        host_port_dict = {}
        for node in node_array:
            ip = node['ip']
            nodename = node['nodename']
            if ip not in host_port_dict:
                port_dict = {}
                host_port_dict[ip] = port_dict
            else:
                port_dict = host_port_dict[ip]

            port = node['port']
            if port in port_dict:
                exists_nodename = port_dict[port][0]
                exists_port_type = port_dict[port][1]
                sys.stderr.write("Detected duplicate port in host(%s), "
                                 "nodename(%s) port (%s) same with nodename(%s) %s!!!\n"
                                 % (ip, nodename, port, exists_nodename, exists_port_type))
                invalid_config = True
            else:
                port_dict[port] = [nodename, 'port']  # 放两项，第一项是nodename，第二项是端口的类型

            if 'pooler_port' in node:
                port = node['pooler_port']
                if port in port_dict:
                    exists_nodename = port_dict[port][0]
                    exists_port_type = port_dict[port][1]
                    sys.stderr.write("Detected duplicate port in host(%s), "
                                     "nodename(%s) pooler port (%s) same with nodename(%s) %s!!!\n"
                                     % (ip, nodename, port, exists_nodename, exists_port_type))
                    invalid_config = True
                else:
                    port_dict[port] = [nodename, 'pooler port']

        # 如果有错误，则直接退出
        if invalid_config:
            sys.stderr.write("Invalid config in %s, please correct it!!!\n" % g_config_file)
            sys.exit(1)


def modify_postgresql_conf(config_file, modify_item_dict):
    """
    修改配置文件:
      1. 如果在文件中只有相应被注释掉的配置项，则新的配置项加在注释掉的配置项后面。
      2. 如果已存在配置项，则替换原有的配置项。
      3. 如果文件中不存在的配置项，则添加到文件尾
    例如modify_item_dict={'port':'5444'}，配置文件中只存在port的注释掉的配置：
      ...
      listen_addresses = '*'
      #port = 5432                            # (change requires restart)
      max_connections = 100                   # (change requires restart)
      ...

    执行后的结果是在此被注释掉的配置项后面加上新的配置项，结果变为：
      ...
      listen_addresses = '*'
      #port = 5432                            # (change requires restart)
      port = 5444
      max_connections = 100                   # (change requires restart)
      ...

    如果配置文件中存在port的注释掉的配置项和未被注释掉的相应的配置项：
      ...
      listen_addresses = '*'
      #port = 5432                            # (change requires restart)
      port = 5433
      max_connections = 100                   # (change requires restart)
      ...

    执行后的结果是在此被注释掉的配置项后面加上新的配置项，结果变为：
      ...
      listen_addresses = '*'
      #port = 5432                            # (change requires restart)
      port = 5444
      max_connections = 100                   # (change requires restart)
      ...

    :param config_file:
    :param modify_item_dict:
    :return:
    """

    fp = file(config_file)
    ori_lines = fp.readlines()
    fp.close()

    # 下面的操作先找各个配置项的位置
    # item_line_num_dict1和item_line_num_dict2分别记录相应的配置项在文件中的行号。
    #   只是item_line_num_dict1字典中key是行号，而value是相应的配置项名称
    #   而item_line_num_dict2字典中key是配置项名称，而value是相应的行号
    item_line_num_dict1 = {}
    item_line_num_dict2 = {}

    # item_comment_line_num_dict1和item_comment_line_num_dict2分别记录配置文件中被注释掉的配置项在文件中的行号。
    item_comment_line_num_dict1 = {}
    item_comment_line_num_dict2 = {}

    i = 0
    for line in ori_lines:
        line = line.strip()
        cells = line.split()
        if len(cells) < 3:
            i += 1
            continue
        if cells[1] != '=':
            i += 1
            continue
        item_name = cells[0].strip()
        if item_name[0] == '#':
            if item_name[1:] in modify_item_dict:
                item_comment_line_num_dict1[i] = item_name[1:]
                item_comment_line_num_dict2[item_name[1:]] = i
        if item_name in modify_item_dict:
            item_line_num_dict1[i] = item_name
            item_line_num_dict2[item_name] = i
        i += 1

    # 如果已存在相应的配置项，即使也存在注释掉的配置项，则就不能在已注释掉的配置项后再加上新配置项了，需要替换掉的已存在的配置项
    for item_name in item_comment_line_num_dict2:
        if item_name in item_line_num_dict2:
            i = item_comment_line_num_dict2[item_name]
            del item_comment_line_num_dict1[i]

    # 如果配置项在item_line_num_dict1中存在或在item_comment_line_num_dict1，则添加新配置项
    i = 0
    new_lines = []
    for line in ori_lines:
        line = line.strip()
        if i in item_line_num_dict1:
            new_line = "%s = %s" % (item_line_num_dict1[i], modify_item_dict[item_line_num_dict1[i]])
            new_lines.append(new_line)
        elif i in item_comment_line_num_dict1:
            # 如新行加到注释行的下一行处
            new_lines.append(line)
            item_name = item_comment_line_num_dict1[i]
            new_line = "%s = %s" % (item_name, modify_item_dict[item_name])
            new_lines.append(new_line)
        else:
            new_lines.append(line)
        i += 1

    # 把配置文件中不存在的配置项，添加到文件尾
    for item_name in modify_item_dict:
        if item_name not in item_line_num_dict2 and item_name not in item_comment_line_num_dict2:
            new_line = "%s = %s" % (item_name, modify_item_dict[item_name])
            new_lines.append(new_line)

    fp = file(config_file, 'w')
    content = '\n'.join(new_lines)
    fp.write(content)
    fp.close()


def remote_chown(remote_ip, file_path, file_user, file_group):
    """
    :param remote_ip:
    :param file_path:
    :param file_user:
    :param file_group:
    :return:
    """

    cmd = "/bin/chown %s:%s %s" % (file_user, file_group, file_path)
    ssh_cmd = '''ssh -o BatchMode=yes -t root@%s "%s" >/dev/null''' % (remote_ip, cmd)
    run_cmd(ssh_cmd)


def remote_chmod(remote_ip, file_path, file_mode):
    """

    :param remote_ip:
    :param file_path:
    :param file_mode:
    :return:
    """

    cmd = "/bin/chmod %s %s" % (file_mode, file_path)
    ssh_cmd = '''ssh -o BatchMode=yes -t root@%s "%s" >/dev/null''' % (remote_ip, cmd)
    run_cmd(ssh_cmd)


def modify_remote_conf(remote_ip, config_file, modify_func, modify_args, is_bak=True):
    """
    编辑远程的配置文件
    :param remote_ip:
    :param config_file:
    :param modify_func:
    :param modify_args:
    :return:
    """

    temp = tempfile.NamedTemporaryFile()
    try:
        cmd = "scp root@%s:%s %s >/dev/null" % (remote_ip, config_file, temp.name)
        run_cmd(cmd)
        modify_func(temp.name, modify_args)

        cmd = 'stat -c %a,%G,%U ' + config_file
        ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (remote_ip, cmd)
        err_code, err_msg, out_msg = run_cmd_result(ssh_cmd)
        if err_code:
            logger.error("Can not run %s: %s" % (ssh_cmd, err_msg))
            return
        cells = out_msg.split(',')
        if len(cells) != 3:
            logger.error("Invalid result from cmd %s : %s" % (ssh_cmd, out_msg))
            return
        file_mode = cells[0].strip()
        file_user = cells[1].strip()
        file_group = cells[2].strip()

        if is_bak:
            # 把文件备份一下后再覆盖
            backup_file = "%s.%s" % (config_file, time.strftime('%Y%m%d%H%M%S'))
            cmd = "cp %s %s" % (config_file, backup_file)
            ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s" >/dev/null''' % (remote_ip, cmd)
            run_cmd(ssh_cmd)
            # 把备份的文件也置成原先相同的用户名、属主及权限
            remote_chown(remote_ip, backup_file, file_user, file_group)
            remote_chmod(remote_ip, backup_file, file_mode)

        cmd = "scp %s root@%s:%s >/dev/null" % (temp.name, remote_ip, config_file)
        run_cmd(cmd)

        # 把文件置成原先相同的用户名、属主及权限
        remote_chown(remote_ip, config_file, file_user, file_group)
        remote_chmod(remote_ip, config_file, file_mode)

    finally:
        # Automatically cleans up the file
        temp.close()


def modify_remote_pg_conf(remote_ip, config_file, modify_item_dict, is_bak=True):
    """
    :param remote_ip:
    :param config_file:
    :param modify_item_dict:
    :param is_bak:
    :return:
    """

    modify_remote_conf(remote_ip, config_file, modify_postgresql_conf, modify_item_dict, is_bak)


def modify_pg_hba_conf(file_name, pos_line):
    """
    :param file_name: pg_hba.conf文件的全路径名
    :param pos_line: 从哪一行开始添加自定义的内容
    :return:
    """

    fp = open(file_name)
    content = fp.read()
    fp.close()
    lines = content.split('\n')
    flag = 0
    new_lines = []
    for line in lines:
        new_lines.append(line)
        if line == pos_line:
            flag = 1
            break

    # 第一次需要加入这个标志行，以后修改就只修改此标志行后面的内容
    if not flag:
        new_lines.append(pos_line)
    new_contents = '\n'.join(new_lines)
    new_contents = "%s\n%s" % (new_contents, g_pg_hba_conf_append_content)

    file_stat = os.stat(file_name)
    # 把原文件改名（后面加上时间戳）
    os.rename(file_name, "%s.%s" % (file_name, time.strftime('%Y%m%d%H%M%S')))
    fp = open(file_name, "w")
    fp.write(new_contents)
    fp.close()
    os.chmod(file_name, file_stat.st_mode)
    os.chown(file_name, file_stat.st_uid, file_stat.st_gid)


def modify_remote_pg_hba(remote_ip, config_file, pos_line):
    """
    :param remote_ip:
    :param config_file:
    :param pos_line:
    :return:
    """

    modify_remote_conf(remote_ip, config_file, modify_pg_hba_conf, pos_line)


def modify_ip_config_file(file_name, ip):
    """
    :param file_name:
    :param ip:
    :return:
    """

    fp = open(file_name)
    content = fp.read()
    fp.close()
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        strip_line = line.strip()
        if not strip_line:
            new_lines.append(line)
            continue
        space_len = line.index(strip_line)
        pre_space = line[:space_len]
        cells = strip_line.split()
        if cells[0] == 'address':
            new_lines.append("%saddress %s" % (pre_space, ip))
        else:
            new_lines.append(line)

    config_file_stat = os.stat(file_name)
    # 把原文件改名（后面加上赶时间戳）
    os.rename(file_name, "%s.%s" % (file_name, time.strftime('%Y%m%d%H%M%S')))
    fp = open(file_name, "w")
    fp.write('\n'.join(new_lines))
    fp.close()
    os.chmod(file_name, config_file_stat.st_mode)


# /lxc_pgx2/gtm/rootfs/home/pgx2/.profile

def modify_profile(file_name, pos_line):
    """
    :param file_name:
    :param pos_line: 从哪一行开始添加自定义的内容
    :return:
    """

    fp = open(file_name)
    content = fp.read()
    fp.close()
    lines = content.split('\n')
    flag = 0
    new_lines = []
    for line in lines:
        new_lines.append(line)
        if line == pos_line:
            flag = 1
            break

    # 第一次需要加入这个标志行，以后修改就只修改此标志行后面的内容
    if not flag:
        new_lines.append(pos_line)
    new_contents = '\n'.join(new_lines)
    new_contents = "%s\n%s" % (new_contents, g_profile_append_content)

    fp = open(file_name, "w")
    fp.write(new_contents)
    fp.close()


def modify_remote_profile(remote_ip, config_file, pos_line, is_bak=True):
    """
    :param remote_ip:
    :param config_file:
    :param is_bak:
    :return:
    """

    modify_remote_conf(remote_ip, config_file, modify_profile, pos_line, is_bak)


def add_lxc(lxc_name, node_ip):
    """
    :param lxc_name:
    :param node_ip:
    :return:
    """

    logger.info("Begin create contain(%s)..." % lxc_name)
    cmd = 'lxc-clone -s %s %s' % (g_lxc['template'], lxc_name)
    run_cmd(cmd)
    logger.info("Create lxc contain(%s) ok." % lxc_name)

    logger.info("Begin modify lxc contain(%s) ip to %s ..." % (lxc_name, node_ip))
    ip_config_file = '%s/%s/rootfs/etc/network/interfaces' % (g_lxc['path'], lxc_name)
    modify_ip_config_file(ip_config_file, node_ip)
    logger.info("Modify lxc contain(%s) ip to %s ok." % (lxc_name, node_ip))

    logger.info("Start lxc container(%s) ..." % lxc_name)
    cmd = 'lxc-start -d -n %s' % lxc_name
    run_cmd(cmd)
    logger.info("Start lxc container(%s) ok." % lxc_name)


def del_lxc(lxc_name):
    cmd = 'lxc-destroy -n %s' % lxc_name
    run_cmd(cmd)
    logger.info("Destroy lxc container(%s) ok." % lxc_name)


def add_os_user(node_ip, os_uid, os_user):
    logger.info("Begin add user and group to host(%s) ..." % node_ip)
    cmd = 'groupadd -g %d %s' % (os_uid, os_user)
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)
    cmd = 'useradd -m -u %(uid)d -g %(uid)d -s /bin/bash %(user)s' % {'uid': os_uid, 'user': os_user}
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)
    logger.info("Add user and group to host(%s) lxc container ok." % node_ip)

    profile_name = '/home/%s/%s' % (os_user, g_profile_name)
    logger.info("Begin modify %s in host(%s) ..." % (profile_name, node_ip))
    modify_remote_profile(node_ip, profile_name, g_profile_pos_line)
    logger.info("Modify modify %s in host(%s) finished." % (profile_name, node_ip))


def add_os_user_all():
    """
    增加集群需要的所有用户
    :return:
    """

    for host in g_host_list:
        os_user_list = host['os_user_list']
        for os_uid in os_user_list:
            node_ip = host['ip']
            os_user = os_user_list[os_uid]
            add_os_user(node_ip, os_uid, os_user)


def del_os_user(node_ip, os_user):
    logger.info("Begin delete user and group in host(%s) ..." % node_ip)
    cmd = 'userdel -r %s' % os_user
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)
    logger.info("Delete user and group to in node(%s)." % node_ip)


def del_os_user_all():
    for host in g_host_list:
        os_user_list = host['os_user_list']
        for os_uid in os_user_list:
            node_ip = host['ip']
            os_user = os_user_list[os_uid]
            del_os_user(node_ip, os_user)


def add_lxc_all():
    for host in g_host_list:
        add_lxc(host['hostname'], host['ip'])


def del_lxc_all():
    for host in g_host_list:
        del_lxc(host['hostname'])


def start_lxc_all():
    for host in g_host_list:
        cmd = 'lxc-start -d -n %s' % host['hostname']
        run_cmd(cmd)


def stop_lxc_all():
    for host in g_host_list:
        cmd = 'lxc-stop -n %s' % host['hostname']
        run_cmd(cmd)


def initdb(is_datanode, nodename, node_ip, os_user, port, pooler_port, pgdata):
    global g_pgx2_user
    global g_gtm
    global g_gtm_proxy

    # 如果PGDATA目录不存在，则建上
    cmd = "if [ ! -d '{pgdata:s}' ] ; then /bin/mkdir -p {pgdata:s};" \
          "/bin/chown {user:s}:{group:s} {pgdata:s};" \
          "/bin/chmod 600 {pgdata:s};  fi" \
        .format(**{'user': os_user, 'group': os_user, 'pgdata': pgdata})
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    cmd = '''su - %s -c 'initdb --nodename=%s --auth-host=md5 -U %s -D %s' ''' % (
        os_user, nodename, g_pgx2_user, pgdata)
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)
    config_file = "%s/postgresql.conf" % pgdata

    gtm_ip = g_gtm['ip']
    gtm_port = g_gtm['port']

    if is_datanode:
        modify_item_dict = dict(g_datanode_conf_dict)
    else:
        modify_item_dict = dict(g_coord_conf_dict)

    # 如果此节点上有gtm proxy，则所此节点的gtm的地址改为127.0.0.1，而port改成gtm_proxy的port，否则直接连接gtm
    for gtm_proxy_node in g_gtm_proxy:
        if gtm_proxy_node['ip'] == node_ip:
            gtm_port = gtm_proxy_node['port']
            gtm_ip = '127.0.0.1'
            break

    modify_item_dict.update({
        "port": "%d" % port,
        "pooler_port": "%d" % pooler_port,
        "gtm_host": "'%s'" % gtm_ip,
        "gtm_port": "%d" % gtm_port
    })
    modify_remote_pg_conf(node_ip, config_file, modify_item_dict)

    pg_hba_conf_file = "%s/pg_hba.conf" % pgdata
    modify_remote_pg_hba(node_ip, pg_hba_conf_file, g_profile_pos_line)


def initgtm():
    """
    :return:
    """

    nodename = g_gtm['nodename']
    node_ip = g_gtm['ip']
    os_user = g_gtm['os_user']
    port = g_gtm['port']
    pgdata = g_gtm['pgdata']

    # 如果PGDATA目录不存在，则建上
    cmd = "if [ ! -d '{pgdata:s}' ] ; then /bin/mkdir -p {pgdata:s};" \
          "/bin/chown {user:s}:{group:s} {pgdata:s};" \
          "/bin/chmod 600 {pgdata:s};  fi" \
        .format(**{'user': os_user, 'group': os_user, 'pgdata': pgdata})
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    cmd = '''su - %s -c 'initgtm -Z gtm -D %s' ''' % (os_user, pgdata)
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    config_file = "%s/gtm.conf" % pgdata
    modify_item_dict = {
        "nodename": "'%s'" % nodename,
        "listen_addresses": "'*'",
        "port": port,
        "startup": "ACT",
    }

    modify_remote_pg_conf(node_ip, config_file, modify_item_dict)


def initgtm_standby():
    """
    """

    # 如果没有配置gtm standby，则退出
    if not g_gtm_standby:
        return

    nodename = g_gtm_standby['nodename']
    node_ip = g_gtm_standby['ip']
    os_user = g_gtm_standby['os_user']
    port = g_gtm_standby['port']
    act_port = g_gtm['port']
    act_ip = g_gtm['ip']
    #pgdata = g_gtm['pgdata'] 
    pgdata = g_gtm_standby['pgdata']
    # 如果PGDATA目录不存在，则建上
    cmd = "if [ ! -d '{pgdata:s}' ] ; then /bin/mkdir -p {pgdata:s};" \
          "/bin/chown {user:s}:{group:s} {pgdata:s};" \
          "/bin/chmod 600 {pgdata:s};  fi" \
        .format(**{'user': os_user, 'group': os_user, 'pgdata': pgdata})
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    cmd = '''su - %s -c 'initgtm -Z gtm -D %s' ''' % (os_user, pgdata)
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    config_file = "%s/gtm.conf" % pgdata
    modify_item_dict = {
        "nodename": "'%s'" % nodename,
        "listen_addresses": "'*'",
        "port": port,
        "startup": "STANDBY",
        "active_host": "'%s'" % act_ip,
        "active_port": act_port
    }
    modify_remote_pg_conf(node_ip, config_file, modify_item_dict)


def initgtm_proxy(nodename, node_ip, os_user, port, gtm_ip, gtm_port, pgdata):
    # 如果PGDATA目录不存在，则建上
    cmd = "if [ ! -d '{pgdata:s}' ] ; then /bin/mkdir -p {pgdata:s};" \
          "/bin/chown {user:s}:{group:s} {pgdata:s};" \
          "/bin/chmod 600 {pgdata:s};  fi" \
        .format(**{'user': os_user, 'group': os_user, 'pgdata': pgdata})
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    cmd = '''su - %s -c 'initgtm -Z gtm_proxy -D %s' ''' % (os_user, pgdata)
    ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    config_file = "%s/gtm_proxy.conf" % pgdata

    modify_item_dict = {
        "nodename": "'%s'" % nodename,
        "listen_addresses": "'*'",
        "port": port,
        "gtm_host": "'%s'" % gtm_ip,
        "gtm_port": gtm_port
    }
    modify_remote_pg_conf(node_ip, config_file, modify_item_dict)


def initgtm_proxy_all():
    """
    """

    # 初使化所有gtm_proxy
    cnt = len(g_gtm_proxy)
    for i in range(cnt):
        nodename = g_gtm_proxy[i]['nodename']
        node_ip = g_gtm_proxy[i]['ip']
        os_user = g_gtm_proxy[i]['os_user']
        port = g_gtm_proxy[i]['port']
        gtm_port = g_gtm['port']
        gtm_ip = g_gtm['ip']
        pgdata = g_gtm_proxy[i]['pgdata']
        initgtm_proxy(nodename, node_ip, os_user, port, gtm_ip, gtm_port, pgdata)


def initdb_datanode():
    """
    初使化(initdb)所有datatnode
    :return:
    """

    # 初使化datanode
    cnt = len(g_datanode)
    for i in range(cnt):
        nodename = g_datanode[i]['nodename']
        node_ip = g_datanode[i]['ip']
        os_user = g_datanode[i]['os_user']
        port = g_datanode[i]['port']
        pooler_port = g_datanode[i]['pooler_port']
        pgdata = g_datanode[i]['pgdata']
        initdb(True, nodename, node_ip, os_user, port, pooler_port, pgdata)


def initdb_coordinator():
    """
    初使化(initdb)所有coordinator
    :return:
    """

    # 初使化coordinator
    cnt = len(g_coord)
    for i in range(cnt):
        nodename = g_coord[i]['nodename']
        node_ip = g_coord[i]['ip']
        os_user = g_coord[i]['os_user']
        port = g_coord[i]['port']
        pooler_port = g_coord[i]['pooler_port']
        pgdata = g_coord[i]['pgdata']
        initdb(False, nodename, node_ip, os_user, port, pooler_port, pgdata)


def initdb_all():
    initgtm()
    initgtm_standby()
    initgtm_proxy_all()
    initdb_datanode()
    initdb_coordinator()


def rm_pgdata_all():
    """
    删除所有的pgdata目录
    :return:
    """

    for node in (g_gtm, g_gtm_standby):
        if not node:
            continue
        node_ip = node['ip']
        os_user = node['os_user']
        pgdata = node['pgdata']
        # 删除gtm的PGDATA目录下的所有内容
        if pgdata:
            cmd = "if [ -d '{pgdata:s}' ] ; then /bin/rm -rf {pgdata:s}/*; fi" \
                .format(**{'user': os_user, 'group': os_user, 'pgdata': pgdata})
            ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
            logger.info("Delete %s in host(%s) ..." % (pgdata, node_ip))
            run_cmd(ssh_cmd)
            # print ssh_cmd

    for node_array in (g_gtm_proxy, g_coord, g_datanode):
        for node in node_array:
            node_ip = node['ip']
            os_user = node['os_user']
            pgdata = node['pgdata']
            # 删除gtm的PGDATA目录下的所有内容
            if pgdata:
                cmd = "if [ -d '{pgdata:s}' ] ; then /bin/rm -rf {pgdata:s}/*; fi" \
                    .format(**{'user': os_user, 'group': os_user, 'pgdata': pgdata})
                ssh_cmd = '''ssh %s "%s"''' % (node_ip, cmd)
                logger.info("Delete %s in host(%s) ..." % (pgdata, node_ip))
                run_cmd(ssh_cmd)
                # print ssh_cmd


def coord_reg_node():
    """
    使用create node把node加到coordinator中
    :return:
    """
    cnt = len(g_coord)
    for i in range(cnt):
        os_user = g_coord[i]['os_user']
        lines = []
        for j in range(cnt):
            nodename = g_coord[j]['nodename']
            ip = g_coord[j]['ip']
            port = g_coord[j]['port']
            if j == i:
                line = '''alter node %s with (host = '%s', port= %d);''' \
                       % (nodename, ip, port)
            else:
                line = '''create node %s with (type = 'coordinator', host = '%s', port= %d);''' \
                       % (nodename, ip, port)
            lines.append(line)

        data_node_cnt = len(g_datanode)
        for j in range(data_node_cnt):
            nodename = g_datanode[j]['nodename']
            ip = g_datanode[j]['ip']
            port = g_datanode[j]['port']
            line = '''create node %s with (type = 'datanode', host = '%s', port= %d);''' \
                   % (nodename, ip, port)
            lines.append(line)

        lines.append('SELECT pgxc_pool_reload();')
        sql_file = "/tmp/create_node.sql"
        fp = file(sql_file, "w")
        fp.write("\n".join(lines))
        fp.close()
        ip = g_coord[i]['ip']
        dest_file = "/home/%s/create_node.sql" % g_coord[i]['os_user']
        cmd = 'scp %s %s:%s' % (sql_file, ip, dest_file)
        run_cmd(cmd)

        cmd = 'chown %s:%s %s' % (os_user, os_user, dest_file)
        ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (ip, cmd)
        run_cmd(ssh_cmd)

        port = g_coord[i]['port']
        cmd = "su - %s -c 'psql -U%s -p %d -d postgres -f create_node.sql'" % (os_user, g_pgx2_user, port)
        ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (ip, cmd)
        run_cmd(ssh_cmd)


def start_pgx2():
    # 启动gtm
    logger.info("Start gtm...")
    node_ip = g_gtm['ip']
    os_user = g_gtm['os_user']
    pgdata = g_gtm['pgdata']
    cmd = "su - %s -c 'gtm_ctl start -Z gtm -D %s' " % (os_user, pgdata)
    ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    if g_gtm_standby:
        logger.info("Start gtm_standby...")
        node_ip = g_gtm_standby['ip']
        os_user = g_gtm_standby['os_user']
        pgdata = g_gtm_standby['pgdata']
        cmd = "su - %s -c 'gtm_ctl start -Z gtm_standby -D %s' " % (os_user, pgdata)
        ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (node_ip, cmd)
        run_cmd(ssh_cmd)

    # 启动gtm_proxy
    cnt = len(g_gtm_proxy)
    for i in range(cnt):
        nodename = g_gtm_proxy[i]['nodename']
        node_ip = g_gtm_proxy[i]['ip']
        os_user = g_gtm_proxy[i]['os_user']
        pgdata = g_gtm_proxy[i]['pgdata']

        logger.info("Start gtmproxy(%s) ..." % nodename)
        cmd = "su - %s -c 'gtm_ctl start -Z gtm_proxy -D %s' " % (os_user, pgdata)
        ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (node_ip, cmd)
        run_cmd(ssh_cmd)

    cnt = len(g_datanode)
    for i in range(cnt):
        nodename = g_datanode[i]['nodename']
        node_ip = g_datanode[i]['ip']
        os_user = g_datanode[i]['os_user']
        pgdata = g_datanode[i]['pgdata']

        logger.info("Start datanode(%s) ..." % nodename)
        cmd = "su - %s -c 'pg_ctl start -Z datanode -D %s'" % (os_user, pgdata)
        ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (node_ip, cmd)
        run_cmd(ssh_cmd)

    cnt = len(g_coord)
    for i in range(cnt):
        nodename = g_coord[i]['nodename']
        node_ip = g_coord[i]['ip']
        os_user = g_coord[i]['os_user']
        pgdata = g_coord[i]['pgdata']

        logger.info("Start coordinator(%s) ..." % nodename)

        cmd = "su - %s -c 'pg_ctl start -Z coordinator -D %s'" % (os_user, pgdata)
        ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (node_ip, cmd)
        run_cmd(ssh_cmd)


def stop_pgx2():
    # 停止时先停coordinator
    cnt = len(g_coord)
    for i in range(cnt):
        nodename = g_coord[i]['nodename']
        node_ip = g_coord[i]['ip']
        os_user = g_coord[i]['os_user']
        pgdata = g_coord[i]['pgdata']

        logger.info("Stop coordinator(%s) ..." % nodename)
        cmd = "su - %s -c 'pg_ctl stop -Z coordinator -m fast -D %s' " % (os_user, pgdata)
        ssh_cmd = '''ssh -o BatchMode=yes %s "%s"''' % (node_ip, cmd)
        run_cmd(ssh_cmd)

    cnt = len(g_datanode)
    for i in range(cnt):
        nodename = g_datanode[i]['nodename']
        node_ip = g_datanode[i]['ip']
        os_user = g_datanode[i]['os_user']
        pgdata = g_datanode[i]['pgdata']

        logger.info("Stop datanode(%s) ..." % nodename)
        cmd = "su - %s -c 'pg_ctl stop -Z datanode -m fast -D %s'" % (os_user, pgdata)
        ssh_cmd = '''ssh -o BatchMode=yes %s "%s"''' % (node_ip, cmd)
        run_cmd(ssh_cmd)

    # 停止gtm_proxy
    cnt = len(g_gtm_proxy)
    for i in range(cnt):
        nodename = g_gtm_proxy[i]['nodename']
        node_ip = g_gtm_proxy[i]['ip']
        os_user = g_gtm_proxy[i]['os_user']
        pgdata = g_gtm_proxy[i]['pgdata']

        logger.info("Stop gtmproxy(%s) ..." % nodename)
        cmd = "su - %s -c 'gtm_ctl stop -Z gtm_proxy -m fast -D %s' " % (os_user, pgdata)
        ssh_cmd = '''ssh -o BatchMode=yes %s "%s"''' % (node_ip, cmd)
        run_cmd(ssh_cmd)

    logger.info("Stop gtm...")
    node_ip = g_gtm['ip']
    os_user = g_gtm['os_user']
    pgdata = g_gtm['pgdata']
    cmd = "su - %s -c 'gtm_ctl stop -Z gtm -m fast -D %s' " % (os_user, pgdata)
    ssh_cmd = '''ssh -o BatchMode=yes %s "%s"''' % (node_ip, cmd)
    run_cmd(ssh_cmd)

    if g_gtm_standby:
        logger.info("Stop gtm_standby...")
        node_ip = g_gtm_standby['ip']
        os_user = g_gtm_standby['os_user']
        pgdata = g_gtm_standby['pgdata']
        cmd = "su - %s -c 'gtm_ctl stop -Z gtm_standby -m fast -D %s' " % (os_user, pgdata)
        ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (node_ip, cmd)
        run_cmd(ssh_cmd)


def get_pgx2_node_status(ip, comm, pidfile):
    """
    获得某一个pgx2的节点的状态
    :return:
    """

    cmd = "test -f %s && head -1 %s" % (pidfile, pidfile)
    ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (ip, cmd)
    err_code, err_msg, out_msg = run_cmd_result(ssh_cmd)
    if err_code == 1:
        return "Stopped"
    elif err_code != 0:  # 无法ssh上去
        return "Unknown"

    pid = out_msg.strip()

    cmd = 'cat /proc/%s/comm && kill -0 %s' % (pid, pid)
    ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (ip, cmd)
    err_code, err_msg, out_msg = run_cmd_result(ssh_cmd)
    if err_code:
        return "Stopped"

    if out_msg.strip() != comm:
        return "Stopped"

    return "Running(pid=%s)" % pid


def status_pgx2():
    """
    显示各个节点的状态
    :return:
    """
    global g_host_list

    # 定义要打印的每一列的标题、长度及其对齐的方向
    prt_item_list = [['hostname',           10, '-'],
                     ['ip',                  9,  ''],
                     ['nodetype',           11, '-'],
                     ['nodename',           12, '-'],
                     ['port',                5,  ''],
                     ['status',             20, '-']
                     ]

    title1 = '  '.join([i[0].center(i[1]) for i in prt_item_list])
    title2 = '  '.join('-'*i[1] for i in prt_item_list)
    format_str = '  '.join('%' + str(i[2]) + str(i[1]) + 's' for i in prt_item_list)
    # 打印标题
    print title1
    print title2

    for host_dict in g_host_list:
        # print "===== %s(%s) =====" % (host_dict['hostname'], host_dict['ip'])
        hostname = host_dict['hostname']
        prt_hostname = hostname
        ip = host_dict['ip']
        prt_ip = ip
        if host_dict['have_gtm']:
            node_dict = g_gtm
            pgdata = node_dict['pgdata']
            pidfile = '%s/gtm.pid' % pgdata
            node_status = get_pgx2_node_status(host_dict['ip'], 'gtm', pidfile)
            print format_str % (
                prt_hostname, prt_ip, 'gtm', node_dict['nodename'],
                node_dict['port'], node_status)
            prt_hostname = ''
            prt_ip = ''

        if host_dict['have_gtm_standby']:
            node_dict = g_gtm_standby
            pgdata = node_dict['pgdata']
            pidfile = '%s/gtm.pid' % pgdata
            node_status = get_pgx2_node_status(host_dict['ip'], 'gtm', pidfile)
            print format_str % (
                prt_hostname, prt_ip, 'gtm_standby', node_dict['nodename'],
                node_dict['port'], node_status)
            prt_hostname = ''
            prt_ip = ''

        if host_dict['have_gtm_proxy']:
            for node_dict in g_gtm_proxy:
                if node_dict['ip'] == host_dict['ip']:
                    pgdata = node_dict['pgdata']
                    pidfile = '%s/gtm_proxy.pid' % pgdata
                    node_status = get_pgx2_node_status(host_dict['ip'], 'gtm_proxy', pidfile)
                    print format_str % (
                        prt_hostname, prt_ip, 'gtm_proxy', node_dict['nodename'],
                        node_dict['port'], node_status)
                    prt_hostname = ''
                    prt_ip = ''

        if host_dict['have_coordinator']:
            for node_dict in g_coord:
                if node_dict['ip'] == host_dict['ip']:
                    pgdata = node_dict['pgdata']
                    pidfile = '%s/postmaster.pid' % pgdata
                    node_status = get_pgx2_node_status(host_dict['ip'], 'postgres', pidfile)
                    print format_str % (
                        prt_hostname, prt_ip, 'coordinator', node_dict['nodename'],
                        node_dict['port'], node_status)
                    prt_hostname = ''
                    prt_ip = ''

        if host_dict['have_datanode']:
            for node_dict in g_datanode:
                if node_dict['ip'] == host_dict['ip']:
                    pgdata = node_dict['pgdata']
                    pidfile = '%s/postmaster.pid' % pgdata
                    node_status = get_pgx2_node_status(host_dict['ip'], 'postgres', pidfile)
                    print format_str % (
                        prt_hostname, prt_ip, 'datanode', node_dict['nodename'],
                        node_dict['port'], node_status)
                    prt_hostname = ''
                    prt_ip = ''


def list_pgx2():
    """
    显示各个节点的信息
    :return:
    """
    global g_host_list

    # 定义要打印的每一列的标题、长度及其对齐的方向
    prt_item_list = [['hostname',           10, '-'],
                     ['ip',                  9, ''],
                     ['nodetype',           11, '-'],
                     ['nodename',           12, '-'],
                     ['port',                5, ''],
                     ['os_user',            10, '-'],
                     ['pgdata',             30, '-']]

    title1 = '  '.join([i[0].center(i[1]) for i in prt_item_list])
    title2 = '  '.join('-'*i[1] for i in prt_item_list)
    format_str = '  '.join('%' + str(i[2]) + str(i[1]) + 's' for i in prt_item_list)
    # 打印标题
    print title1
    print title2

    for host_dict in g_host_list:
        # print "===== %s(%s) =====" % (host_dict['hostname'], host_dict['ip'])
        hostname = host_dict['hostname']
        prt_hostname = hostname
        ip = host_dict['ip']
        prt_ip = ip
        if host_dict['have_gtm']:
            node_dict = g_gtm
            pgdata = node_dict['pgdata']
            print format_str % (
                prt_hostname, prt_ip, 'gtm', node_dict['nodename'],
                node_dict['port'], node_dict['os_user'], pgdata)
            prt_hostname = ''
            prt_ip = ''

        if host_dict['have_gtm_standby']:
            node_dict = g_gtm_standby
            pgdata = node_dict['pgdata']
            print format_str % (
                prt_hostname, prt_ip, 'gtm_standby', node_dict['nodename'],
                node_dict['port'], node_dict['os_user'], pgdata)
            prt_hostname = ''
            prt_ip = ''

        if host_dict['have_gtm_proxy']:
            for node_dict in g_gtm_proxy:
                if node_dict['ip'] == host_dict['ip']:
                    pgdata = node_dict['pgdata']
                    print format_str % (
                        prt_hostname, prt_ip, 'gtm_proxy', node_dict['nodename'],
                        node_dict['port'], node_dict['os_user'], pgdata)
                    prt_hostname = ''
                    prt_ip = ''

        if host_dict['have_coordinator']:
            for node_dict in g_coord:
                if node_dict['ip'] == host_dict['ip']:
                    pgdata = node_dict['pgdata']
                    print format_str % (
                        prt_hostname, prt_ip, 'coordinator', node_dict['nodename'],
                        node_dict['port'], node_dict['os_user'], pgdata)
                    prt_hostname = ''
                    prt_ip = ''

        if host_dict['have_datanode']:
            for node_dict in g_datanode:
                if node_dict['ip'] == host_dict['ip']:
                    pgdata = node_dict['pgdata']
                    print format_str % (
                        prt_hostname, prt_ip, 'datanode', node_dict['nodename'],
                        node_dict['port'], node_dict['os_user'], pgdata)
                    prt_hostname = ''
                    prt_ip = ''


def set_pgx2_node_conf(node_type, key, value):
    """
    :param node_type: 结点类型，可以为gtm,gtm_standby, gtm_proxy, datanode, coordinator
    :param key:
    :param value:
    :return:
    """

    # config_file = ''
    node_info_list = []
    if node_type == 'gtm':
        node_info_list.append(g_gtm)
        config_file = 'gtm.conf'
    elif node_type == 'gtm_standby':
        node_info_list.append(g_gtm_standby)
        config_file = 'gtm.conf'
    elif node_type == 'gtm_proxy':
        node_info_list = g_gtm_proxy
        config_file = 'gtm.conf'
    elif node_type == 'coordinator':
        node_info_list = g_coord
        config_file = 'postgresql.conf'
    elif node_type == 'datanode':
        node_info_list = g_datanode
        config_file = 'postgresql.conf'
    else:
        logger.error("Unknown node type: %s, must be in gtm, gtm_standby, gtm_proxy, coordinator, datanode."
                     % node_type)
        sys.exit(1)

    cnt = len(node_info_list)
    for i in range(cnt):
        nodename = node_info_list[i]['nodename']
        node_ip = node_info_list[i]['ip']
        os_user = node_info_list[i]['os_user']
        pgdata = node_info_list[i]['pgdata']

        temp = tempfile.NamedTemporaryFile()
        try:
            logger.info("Modify node(%s) %s ..." % (nodename, config_file))
            cmd = "scp root@%s:%s/%s %s" % (node_ip, pgdata, config_file, temp.name)
            run_cmd(cmd)
            modify_item_dict = {key: value}
            modify_postgresql_conf(temp.name, modify_item_dict)

            # 把文件备份一下后再覆盖
            cmd = "su - {user:s} -c 'cp {pgdata:s}/{conf:s} {pgdata:s}/{conf:s}.{tm:s}'" \
                .format(**{'user': os_user, 'pgdata': pgdata, 'conf': config_file, 'tm': time.strftime('%Y%m%d%H%M%S')})
            ssh_cmd = '''ssh -o BatchMode=yes -t %s "%s"''' % (node_ip, cmd)
            run_cmd(ssh_cmd)

            cmd = "scp %s root@%s:%s/%s" % (temp.name, node_ip, pgdata, config_file)
            run_cmd(cmd)

        finally:
            # Automatically cleans up the file
            temp.close()


def check_and_init_log(loglevel):
    log_level_dict = {"debug": logging.DEBUG,
                      "info": logging.INFO,
                      "warn": logging.WARN,
                      "error": logging.ERROR,
                      "critical": logging.CRITICAL,
                      }
    if loglevel.lower() not in log_level_dict:
        sys.stderr.write("Unknown loglevel: " + loglevel)
        sys.exit(-1)

    # 初使用化日志
    log_level = log_level_dict[loglevel.lower()]
    init_logger(log_level)


def init_options_parser():
    """
    :return:
    """

    usage = "%%prog %s [options]\n" % sys.argv[1]
    parser = OptionParser(usage=usage)
    parser.add_option("-l", "--loglevel", action="store", dest="loglevel", default="info",
                      help="Specifies log level:  debug, info, warn, error, critical, default is info")
    return parser


def action_lxc_add():
    parser = init_options_parser()

    parser.add_option("-n", "--lxc_name", action="store", dest="lxc_name", default="",
                      help="The name of the lxc container which will be added.")

    parser.add_option("-i", "--ip", action="store", dest="ip", default="",
                      help="The ip address of the lxc container")

    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)

    add_lxc(options.lxc_name, options.ip)


def action_lxc_del():
    parser = init_options_parser()

    parser.add_option("-n", "--lxc_name", action="store", dest="lxc_name", default="",
                      help="The name of the lxc container which will be deleted.")

    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)
    cmd = 'lxc-destroy -n %s' % options.lxc_name
    run_cmd(cmd)


def action_add_os_user():
    parser = init_options_parser()

    parser.add_option("-i", "--ip", action="store", dest="ip", default="",
                      help="The ip address of the lxc container")

    parser.add_option("-u", "--uid", action="store", dest="uid", default="",
                      help="The uid of the user")
    parser.add_option("-U", "--user", action="store", dest="user", default="",
                      help="The username")

    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)
    add_os_user(options.ip, int(options.uid), options.user)


def action_lxc_add_all():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    add_lxc_all()


def action_lxc_del_all():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    del_lxc_all()


def action_lxc_start_all():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    start_lxc_all()


def action_lxc_stop_all():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    stop_lxc_all()


def action_add_os_user_all():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    add_os_user_all()


def action_del_os_user_all():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    del_os_user_all()


def action_initdb():
    parser = init_options_parser()

    parser.add_option("-n", "--nodename", action="store", dest="nodename", default="",
                      help="pgx2 nodename.")

    parser.add_option("-i", "--ip", action="store", dest="ip", default="",
                      help="The ip address of the host")

    parser.add_option("-c", "--coordinator", action="store_true", dest="coordinator",
                      help="Create a coordinator")

    parser.add_option("-d", "--datanode", action="store_true", dest="datanode",
                      help="Create a coordinator")

    parser.add_option("-p", "--port", action="store", dest="port", default="",
                      help="The port of the datanode")

    parser.add_option("-P", "--pooler_port", action="store", dest="pooler_port", default="",
                      help="The pooler port of the datanode")

    parser.add_option("-U", "--user", action="store", dest="user", default="",
                      help="The username")

    parser.add_option("-D", "--pgdata", action="store", dest="pgdata", default="",
                      help="The path of PGDATA")

    (options, args) = parser.parse_args(sys.argv[2:])
    if len(args) == 0:
        parser.print_help()
        sys.exit(1)

    check_and_init_log(options.loglevel)

    if options.datanode and options.coordinator:
        logger.error("Parameter -d and -c can not both be specified!")
        sys.exit(1)
    is_datanode = options.datanode
    initdb(is_datanode, options.nodename, options.ip, options.user, int(options.port),
           int(options.pooler_port), options.pgdata)


def action_initgtm():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    initgtm()


def action_initgtm_standby():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    initgtm_standby()


def action_initgtm_proxy():
    parser = init_options_parser()

    parser.add_option("-n", "--lxc_name", action="store", dest="lxc_name", default="",
                      help="The name of the lxc.")

    parser.add_option("-N", "--nodename", action="store", dest="nodename", default="",
                      help="pgx2 nodename.")

    parser.add_option("-i", "--ip", action="store", dest="ip", default="",
                      help="The ip address of the lxc")

    parser.add_option("-p", "--port", action="store", dest="port", default="",
                      help="The port of the datanode")

    parser.add_option("-I", "--gtmip", action="store", dest="gtm_ip", default="",
                      help="The ip address of the gtm")

    parser.add_option("-P", "--gtmport", action="store", dest="gtm_port", default="",
                      help="The port of the gtm")

    parser.add_option("-U", "--user", action="store", dest="user", default="",
                      help="The gtm proxy os username")

    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)

    initgtm_proxy(options.lxc_name, options.nodename, options.ip, options.user,
                  int(options.port), options.gtm_ip, int(options.gtm_port))


def action_initdb_all():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)

    initdb_all()


def action_rm_pgdata_all():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)

    rm_pgdata_all()


def action_coord_reg_node():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)

    coord_reg_node()


def action_start():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)
    start_pgx2()


def action_stop():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    stop_pgx2()


def action_status():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)
    status_pgx2()


def action_list():
    parser = init_options_parser()
    (options, args) = parser.parse_args(sys.argv[1:])

    check_and_init_log(options.loglevel)
    list_pgx2()


def action_psql():
    parser = init_options_parser()
    parser.add_option("-d", "--datanode", action="store", dest="datanode", type='int', default=0,
                      help="Specify the index of datanode, can be 1,2,3...")
    parser.add_option("-c", "--coordinator", action="store", dest="coordinator", type='int', default=0,
                      help="Specify the index of coordinator, can be 1,2,3...")

    parser.add_option("-D", "--database", action="store", dest="database", default='postgres',
                      help="Specify the database")

    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    if options.datanode and options.coordinator:
        logger.error("Parameter -d and -c can not both be specified!")
        sys.exit(1)

    # port = 5432
    # node_ip = '127.0.0.1'
    if options.datanode:
        node_ip = g_datanode[options.datanode - 1]['ip']
        port = g_datanode[options.datanode - 1]['port']
    elif options.coordinator:
        node_ip = g_coord[options.coordinator - 1]['ip']
        port = g_coord[options.coordinator - 1]['port']
    else:
        parser.print_help()
        sys.exit(1)

    cmd = '%s/bin/psql -p%d -U%s %s' % (g_pgx2_install_dir, port, g_pgx2_user, options.database)
    os.execl('/usr/bin/ssh', '/usr/bin/ssh', '-t', node_ip, cmd)


def action_set():
    parser = init_options_parser()
    parser.add_option("-d", "--datanode", action="store_true", dest="datanode",
                      help="Set configuration of datanode.")
    parser.add_option("-c", "--coordinator", action="store_true", dest="coordinator",
                      help="Set configuration of coordinator.")

    parser.add_option("-k", "--key", action="store", dest="key", default='',
                      help="Specify key of configuration")

    parser.add_option("-v", "--value", action="store", dest="value", default='',
                      help="Specify key of configuration")

    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    if options.datanode and options.coordinator:
        logger.error("Parameter -d and -c can not both be specified!")
        parser.print_help()
        sys.exit(1)

    if options.datanode:
        set_pgx2_node_conf('datanode', options.key, options.value)
    elif options.coordinator:
        set_pgx2_node_conf('coordinator', options.key, options.value)
    else:
        parser.print_help()


def action_get():
    parser = init_options_parser()
    parser.add_option("-d", "--datanode", action="store_true", dest="datanode",
                      help="Set configuration of datanode.")
    parser.add_option("-c", "--coordinator", action="store_true", dest="coordinator",
                      help="Set configuration of coordinator.")

    parser.add_option("-k", "--key", action="store", dest="key", default='',
                      help="Specify key of configuration")

    (options, args) = parser.parse_args(sys.argv[1:])
    check_and_init_log(options.loglevel)

    if options.datanode and options.coordinator:
        logger.error("Parameter -d and -c can not both be specified!")
        parser.print_help()
        sys.exit(1)

    if options.datanode:
        pass
        # get_pgx2_node_conf('datanode', options.key)
    elif options.coordinator:
        pass
        # get_pgx2_node_conf('coordinator', options.key)
    else:
        parser.print_help()


def action_check_config():
    sys.stdout.write("Check OK.\n")


def main():
    cmd_def_list = [
        [action_check_config, 'check_config', 'check configuration.'],
        [action_lxc_add, 'lxc_add', 'add a lxc virtual machine.'],
        [action_lxc_del, 'lxc_del', 'delete a lxc virtual machine by name.'],
        [action_lxc_add_all, 'lxc_add_all', 'add all lxc virtual machine.'],
        [action_lxc_del_all, 'lxc_del_all', 'delete all lxc virtual machine.'],
        [action_lxc_start_all, 'lxc_start_all', 'start all lxc virtual machine.'],
        [action_lxc_stop_all, 'lxc_stop_all', 'stop all lxc virtual machine.'],
        [action_add_os_user, 'add_os_user', 'add user to lxc virtual machine.'],
        [action_add_os_user_all, 'add_os_user_all', 'add every user to all lxc virtual machine.'],
        [action_del_os_user_all, 'del_os_user_all', 'delete every user to all lxc virtual machine.'],
        [action_initdb, 'initdb', 'initdb in a datanode.'],
        [action_initgtm, 'initgtm', 'initgtm.'],
        [action_initgtm_standby, 'initgtm_standby', 'initgtm_standby.'],
        [action_initgtm_proxy, 'initgtm_proxy', 'initgtm_proxy.'],
        [action_initdb_all, 'initdb_all', 'All pgx2 initdb.'],
        [action_rm_pgdata_all, 'rm_pgdata_all', 'delete all pgdata directory.'],
        [action_start, 'start', 'start pgx2.'],
        [action_stop, 'stop', 'stop pgx2.'],
        [action_status, 'status', 'show status of pgx2.'],
        [action_list, 'list', 'show node info of pgx2.'],
        [action_coord_reg_node, 'coord_reg_node', 'Register node to coordinator.'],
        [action_psql, 'psql', 'Using psql connect to coordinator or datanode.'],
        [action_set, 'set', 'Set database configuration in postgresql.conf'],
        [action_get, 'get', 'Get database configuration in postgresql.conf'],
    ]

    prog_name = os.path.basename(sys.argv[0])
    usage = "%s v%s Author: osdba\n" \
            "usage: %s <command> [options]\n" \
            "    command can be one of the following:" % (prog_name, g_version, prog_name)

    for cmd_item in cmd_def_list:
        usage += "\n      %-16s: %s" % (cmd_item[1], cmd_item[2])

    cmd_name_list = []
    for cmd_item in cmd_def_list:
        cmd_name_list.append(cmd_item[1])

    if len(sys.argv) == 1:
        print usage
        sys.exit(0)

    # 装载配置并检查
    load_config()
    # print "======= host ====="
    # print repr(g_host_list)
    # print "======= gtm ======"
    # print repr(g_gtm)
    # print "======= gtm_standby ======"
    # print repr(g_gtm_standby)
    # print "======= gtm_proxy ======"
    # print repr(g_gtm_proxy)
    # print "======= datanode ======"
    # print repr(g_datanode)
    # print "======= coordinator ======"
    # print repr(g_coord)

    for cmd_item in cmd_def_list:
        if sys.argv[1] == cmd_item[1]:
            print "=== %s V0.1 Author: osdba ===\n" % prog_name
            cmd_item[0]()
            sys.exit(0)

    print usage
    sys.exit(1)


if __name__ == "__main__":
    main()
