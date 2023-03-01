#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Jenkins是一个开源的持续集成的服务器, 用于监控持续重复的工作, 旨在提供一个开放易用的软件平台, 使软件的持续集成变成可能
    Jenkins扫描类: 
        1. jenkins 远程命令执行
            CVE-2018-1000861

        2. jenkins 未授权访问
            暂无编号
                Payload: https://blog.csdn.net/weixin_40412037/article/details/120369441


file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
file:///C:/Windows/System32/drivers/etc/hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Jenkins.cve_2018_1000861 import cve_2018_1000861_scan
from payloads.Jenkins.unauth import unauth_scan

class Jenkins():
    def __init__(self):
        self.app_name = 'Jenkins'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2018_1000861_scan, clients=clients),
            thread(target=unauth_scan, clients=clients),
        ]

jenkins = Jenkins()
