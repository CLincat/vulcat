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

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Supervisor.cve_2017_11610 import cve_2017_11610_scan

class Supervisor():
    def __init__(self):
        self.app_name = 'Supervisor'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2017_11610_scan, clients=clients)
        ]

Supervisor.cve_2017_11610_scan = cve_2017_11610_scan

supervisor = Supervisor()
