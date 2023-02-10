#!/usr/bin/env python3
# -*- coding:utf-8 -*-

''' 该POC没有经过实际环境验证(暂未找到漏洞环境, 还没测试POC准确性)

    Keycloak扫描类: 
        Keycloak SSRF
            CVE-2020-10770
                Payload: Awvs scanner
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Keycloak.cve_2020_10770 import cve_2020_10770_scan

class Keycloak():
    def __init__(self):
        self.app_name = 'Keycloak'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2020_10770_scan, clients=clients)
        ]

Keycloak.cve_2020_10770_scan = cve_2020_10770_scan

keycloak = Keycloak()