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

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Nodejs.cve_2017_14849 import cve_2017_14849_scan
from payloads.Nodejs.cve_2021_21315 import cve_2021_21315_scan

class Nodejs():
    def __init__(self):
        self.app_name = 'Node.js'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2017_14849_scan, clients=clients),
            thread(target=self.cve_2021_21315_scan, clients=clients)
        ]

Nodejs.cve_2017_14849_scan = cve_2017_14849_scan
Nodejs.cve_2021_21315_scan = cve_2021_21315_scan

nodejs = Nodejs()
