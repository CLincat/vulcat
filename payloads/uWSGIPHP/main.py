#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
uWSGI是一款Web应用程序服务器, 它实现了WSGI、uwsgi和http等协议, 并支持通过插件来运行各种语言
    uWSGI PHP扫描类: 
        uWSGI PHP目录穿越漏洞
            CVE-2018-7490
                Payload: https://vulhub.org/#/environments/uwsgi/CVE-2018-7490/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.uWSGIPHP.cve_2018_7490 import cve_2018_7490_scan

class uWSGI_PHP():
    def __init__(self):
        self.app_name = 'uWSGI-PHP'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2018_7490_scan, clients=clients)
        ]

uWSGI_PHP.cve_2018_7490_scan = cve_2018_7490_scan

uwsgiphp = uWSGI_PHP()
