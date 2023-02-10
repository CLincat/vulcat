#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''

    Apache Hadoop扫描类: 
        Hadoop YARN ResourceManager 未授权访问
            暂无编号
                Payload: https://vulhub.org/#/environments/hadoop/unauthorized-yarn/
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheHadoop.new_unauth import apache_hadoop_unauthorized_scan

class ApacheHadoop():
    def __init__(self):
        self.app_name = 'ApacheHadoop'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.unauth_scan, clients=clients)
        ]

ApacheHadoop.unauth_scan = apache_hadoop_unauthorized_scan

hadoop = ApacheHadoop()
