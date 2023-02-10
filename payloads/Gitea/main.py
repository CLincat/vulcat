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

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Gitea.unauth import unauth_scan

class Gitea():
    def __init__(self):
        self.app_name = 'Gitea'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.unauth_scan, clients=clients)
        ]

Gitea.unauth_scan = unauth_scan

gitea = Gitea()
