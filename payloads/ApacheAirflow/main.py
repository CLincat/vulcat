#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheAirflow扫描类: 
        Airflow 身份验证绕过漏洞
            CVE-2020-17526
                Payload: https://vulhub.org/#/environments/airflow/CVE-2020-17526/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
# from lib.tool.md5 import md5
from lib.tool.thread import thread
from payloads.ApacheAirflow.cve_2020_17526 import cve_2020_17526_scan

class Airflow():
    def __init__(self):
        self.app_name = 'ApacheAirflow'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2020_17526_scan, clients=clients)
        ]

Airflow.cve_2020_17526_scan = cve_2020_17526_scan

airflow = Airflow()