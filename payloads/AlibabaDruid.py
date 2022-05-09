#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    AlibabaDruid扫描类: 
        druid 未授权访问
            暂无编号
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Druid():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'AlibabaDruid'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.alibaba_druid_unauthorized_payloads = [
            {
                'path': 'druid/index.html',
                'data': ''
            }
        ]

    def alibaba_druid_unauthorized_scan(self, url):
        ''' druid未授权访问漏洞
                攻击者可利用druid管理面板, 查看Session信息, 并利用泄露的Session登录后台(有时候可能没有Session)
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'druid-unauth'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}
        
        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.alibaba_druid_unauthorized_payloads:# * Payload
            path = payload['path']                              # * Path
            data = payload['data']                              # * Data
            target = url + path                                 # * Target

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

            if ('Stat Index' in res.text):
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

    def addscan(self, url):
        return [
            thread(target=self.alibaba_druid_unauthorized_scan, url=url),
        ]

alidruid = Druid()