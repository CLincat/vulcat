#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Apache SkyWalking是阿帕奇的一款主要用于微服务、云原生和基于容器等环境的应用程序性能监视器
    Apache SkyWalking扫描类: 
        1. SkyWalking SQL注入
            CVE-2020-9483
                Payload: https://vulhub.org/#/environments/skywalking/8.3.0-sqli/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheSkyWalking.cve_2020_9483 import cve_2020_9483_scan

class ApacheSkyWalking():
    def __init__(self):
        self.app_name = 'ApacheSkyWalking'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2020_9483_scan, clients=clients)
        ]

skywalking = ApacheSkyWalking()
