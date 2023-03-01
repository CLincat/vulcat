#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    AlibabaNacos扫描类: 
        Nacos 未授权访问
            CVE-2021-29441(nacos-4593)
                https://github.com/alibaba/nacos/issues/4593
'''

from lib.tool.thread import thread
from payloads.AlibabaNacos.cve_2021_29441 import cve_2021_29441_scan

class Nacos():
    def __init__(self):
        self.app_name = 'AlibabaNacos'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2021_29441_scan, clients=clients),
        ]

nacos = Nacos()