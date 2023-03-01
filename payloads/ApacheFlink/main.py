#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheFlink扫描类: 
        Flink 任意文件读取
            CVE-2020-17519
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheFlink.cve_2020_17519 import cve_2020_17519_scan

class Flink():
    def __init__(self):
        self.app_name = 'ApacheFlink'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2020_17519_scan, clients=clients)
        ]

flink = Flink()