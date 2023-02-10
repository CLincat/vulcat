#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Apache APISIX是一个高性能API网关
    ApacheAPISIX扫描类: 
        Apache APISIX默认密钥漏洞
            CVE-2020-13945
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheAPISIX.cve_2020_13945 import cve_2020_13945_scan

class APISIX():
    def __init__(self):
        self.app_name = 'ApacheAPISIX'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2020_13945_scan, clients=clients)
        ]

APISIX.cve_2020_13945_scan = cve_2020_13945_scan

apisix = APISIX()