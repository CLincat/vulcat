#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''

    Gitlab扫描类: 
        1. GitLab Pre-Auth 远程命令执行 
            CVE-2021-22205
                Payload: https://vulhub.org/#/environments/gitlab/CVE-2021-22205/
                反弹shell: https://blog.csdn.net/weixin_46137328/article/details/121551162

        2. Gitlab CI Lint API未授权 SSRF
            CVE-2021-22214
                Payload: https://cloud.tencent.com/developer/article/1851527


file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
file:///C:/Windows/System32/drivers/etc/hosts
'''

from lib.initial.config import config
from lib.tool.thread import thread
from thirdparty import requests
from payloads.Gitlab.cve_2021_22205 import cve_2021_22205_scan
from payloads.Gitlab.cve_2021_22214 import cve_2021_22214_scan

class Gitlab():
    def __init__(self):
        self.app_name = 'Gitlab'
        self.session = requests.session()

        self.headers = config.get('headers')
        self.timeout = config.get('timeout')
        self.proxies = config.get('proxies')

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2021_22205_scan, clients=clients),
            thread(target=self.cve_2021_22214_scan, clients=clients)
        ]

Gitlab.cve_2021_22205_scan = cve_2021_22205_scan
Gitlab.cve_2021_22214_scan = cve_2021_22214_scan

gitlab = Gitlab()
