#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Atlassian Confluence扫描类: 
        1. Confluence路径遍历和命令执行
            CVE-2019-3396
                Payload: https://vulhub.org/#/environments/confluence/CVE-2019-3396/

        2. Confluence Server Webwork Pre-Auth OGNL表达式命令注入
            CVE-2021-26084
                Payload: https://vulhub.org/#/environments/confluence/CVE-2021-26084/

        3. Confluence任意文件包含
            CVE-2015-8399
                Payload: https://blog.csdn.net/caiqiiqi/article/details/106004003

        4. Confluence远程代码执行
            CVE-2022-26134
                Payload-1: https://github.com/vulhub/vulhub/tree/master/confluence/CVE-2022-26134
                Payload-2: https://github.com/SNCKER/CVE-2022-26134

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
file:///C:/Windows/System32/drivers/etc/hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.AtlassianConfluence.cve_2015_8399 import cve_2015_8399_scan
from payloads.AtlassianConfluence.cve_2019_3396 import cve_2019_3396_scan
from payloads.AtlassianConfluence.cve_2021_26084 import cve_2021_26084_scan
from payloads.AtlassianConfluence.cve_2022_26134 import cve_2022_26134_scan

class AtlassianConfluence():
    def __init__(self):
        self.app_name = 'AtlassianConfluence'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2015_8399_scan, clients=clients),
            thread(target=self.cve_2019_3396_scan, clients=clients),
            thread(target=self.cve_2021_26084_scan, clients=clients),
            thread(target=self.cve_2022_26134_scan, clients=clients)
        ]

AtlassianConfluence.cve_2015_8399_scan = cve_2015_8399_scan
AtlassianConfluence.cve_2019_3396_scan = cve_2019_3396_scan
AtlassianConfluence.cve_2021_26084_scan = cve_2021_26084_scan
AtlassianConfluence.cve_2022_26134_scan = cve_2022_26134_scan

confluence = AtlassianConfluence()
