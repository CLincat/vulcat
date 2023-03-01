#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
GoCD是一个开源的持续集成和持续交付系统，可以在持续交付过程中执行编译，自动化测试，自动部署等等
    GoCD扫描类: 
        1. GoCD Business Continuity 任意文件读取漏洞
            CVE-2021-43287
                Payload: http://wiki.peiqi.tech/wiki/webserver/GoCD/GoCD%20plugin%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E%20CVE-2021-43287.html
                         https://avd.aliyun.com/detail?id=AVD-2021-43287

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.GoCD.cve_2021_43287 import cve_2021_43287_scan

class GoCD():
    def __init__(self):
        self.app_name = 'GoCD'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2021_43287_scan, clients=clients)
        ]

gocd = GoCD()
