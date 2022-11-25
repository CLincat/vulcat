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

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.thread import thread
from payloads.ApacheAirflow.cve_2020_17526 import cve_2020_17526_scan

class Airflow():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheAirflow'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_17526_payloads = [
            {
                'path': 'admin/airflow/login',
                'data': ''
            },
            {
                'path': 'airflow/login',
                'data': ''
            },
            {
                'path': 'login',
                'data': ''
            },
            {
                'path': '',
                'data': ''
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_17526_scan, url=url)
        ]

Airflow.cve_2020_17526_scan = cve_2020_17526_scan

airflow = Airflow()