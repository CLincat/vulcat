#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheTomcat扫描类: 
        Tomcat PUT方法任意文件写入漏洞
            CVE-2017-12615
                Payload: https://vulhub.org/#/environments/tomcat/CVE-2017-12615/
                         https://mp.weixin.qq.com/s?__biz=MzI1NDg4MTIxMw==&mid=2247483659&idx=1&sn=c23b3a3b3b43d70999bdbe644e79f7e5
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheTomcat.cve_2017_12615 import cve_2017_12615_scan

class Tomcat():
    def __init__(self):
        self.app_name = 'ApacheTomcat'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2017_12615_scan, clients=clients),
        ]

Tomcat.cve_2017_12615_scan = cve_2017_12615_scan

tomcat = Tomcat()