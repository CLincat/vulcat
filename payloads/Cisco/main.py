#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Cisco相关设备/页面扫描类: 
        Cisco ASA设备/FTD设备 XSS跨站脚本攻击
            CVE-2020-3580
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Cisco.cve_2020_3580 import cve_2020_3580_scan

class Cisco():
    def __init__(self):
        self.app_name = 'Cisco'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2020_3580_scan, clients=clients)
        ]

Cisco.cve_2020_3580_scan = cve_2020_3580_scan

cisco = Cisco()