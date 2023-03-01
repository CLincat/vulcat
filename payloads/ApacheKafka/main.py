#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
(还未测试准确性)

Apache Kafka 是一个开源分布式事件流平台，可用于高性能数据管道、流分析、数据集成和任务关键型应用程序
    Apache Kafka扫描类: 
        Apache Kafka Connect 远程代码执行
            CVE-2023-25194
                Payload: https://github.com/ohnonoyesyes/CVE-2023-25194

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheKafka.cve_2023_25194 import cve_2023_25194_scan

class ApacheKafka():
    def __init__(self):
        self.app_name = 'ApacheKafka'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2023_25194_scan, clients=clients)
        ]

kafka = ApacheKafka()
