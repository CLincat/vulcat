#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
AppWeb是Embedthis Software LLC公司负责开发维护的一个基于GPL开源协议的嵌入式Web Server
        他使用C/C++来编写, 能够运行在几乎先进所有流行的操作系统上
        当然他最主要的应用场景还是为嵌入式设备提供Web Application容器
    AppWeb扫描类: 
        AppWeb 身份认证绕过
            CVE-2018-8715
                Payload: https://vulhub.org/#/environments/appweb/CVE-2018-8715/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.thread import thread
from payloads.AppWeb.cve_2018_8715 import cve_2018_8715_scan

class AppWeb():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'AppWeb'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_8715_payloads = [                 # * 是不是很神奇, payload居然是空的
            {
                'path': '',
                'data': ''
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2018_8715_scan, url=url)
        ]

AppWeb.cve_2018_8715_scan = cve_2018_8715_scan

appweb = AppWeb()
