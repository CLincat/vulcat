#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Apache Unomi 是一个基于标准的客户数据平台(CDP, Customer Data Platform)
用于管理在线客户和访客等信息, 以提供符合访客隐私规则的个性化体验
    ApacheUnomi扫描类: 
        Apache Unomi 远程表达式代码执行
            CVE-2020-13942
                Payload: https://vulhub.org/#/environments/unomi/CVE-2020-13942/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheUnomi.cve_2020_13942 import cve_2020_13942_scan

class ApacheUnomi():
    def __init__(self):
        self.app_name = 'ApacheUnomi'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2020_13942_scan, clients=clients)
        ]

ApacheUnomi.cve_2020_13942_scan = cve_2020_13942_scan

apacheunomi = ApacheUnomi()
