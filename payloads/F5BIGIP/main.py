#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    F5-BIG-IP扫描类: 
        1. F5-BIG-IP 远程代码执行
            CVE-2020-5902
                Payload: https://github.com/jas502n/CVE-2020-5902

        2. F5-BIG-IP 身份认证绕过RCE
            CVE-2022-1388
                Payload: http://www.hackdig.com/05/hack-657629.htm

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.F5BIGIP.cve_2020_5902 import cve_2020_5902_scan
from payloads.F5BIGIP.cve_2022_1388 import cve_2022_1388_scan

class F5_BIG_IP():
    def __init__(self):
        self.app_name = 'F5-BIG-IP'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2020_5902_scan, clients=clients),
            thread(target=cve_2022_1388_scan, clients=clients)
        ]

f5bigip = F5_BIG_IP()
