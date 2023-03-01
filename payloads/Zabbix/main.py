#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
zabbix是一款服务器监控软件, 其由server、agent、web等模块组成, 其中web模块由PHP编写, 用来显示数据库中的结果
    Zabbix扫描类: 
        1. zabbix latest.php SQL注入
            CVE-2016-10134
                Payload: https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2016-10134


file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Zabbix.cve_2016_10134 import cve_2016_10134_scan

class Zabbix():
    def __init__(self):
        self.app_name = 'Zabbix'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2016_10134_scan, clients=clients)
        ]

zabbix = Zabbix()
