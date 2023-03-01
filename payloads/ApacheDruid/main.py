#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Apache Druid 是一个集时间序列数据库、数据仓库和全文检索系统特点于一体的分析性数据平台 (不支持Windows平台)
    Apache Druid扫描类: 
        1. Apache Druid 远程代码执行
            CVE-2021-25646
                Payload: https://www.freebuf.com/vuls/263276.html
                         https://cloud.tencent.com/developer/article/1797515

        2. Apache Druid任意文件读取
            CVE-2021-36749
                Payload: https://cloud.tencent.com/developer/article/1942458

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheDruid.cve_2021_25646 import cve_2021_25646_scan
from payloads.ApacheDruid.cve_2021_36749 import cve_2021_36749_scan

class ApacheDruid():
    def __init__(self):
        self.app_name = 'ApacheDruid'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2021_25646_scan, clients=clients),
            thread(target=cve_2021_36749_scan, clients=clients),
        ]

apachedruid = ApacheDruid()
