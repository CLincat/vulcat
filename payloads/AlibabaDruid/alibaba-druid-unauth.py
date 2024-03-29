#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
druid未授权访问漏洞
    攻击者可利用druid管理面板, 查看Session信息, 并利用泄露的Session登录后台(有时候可能没有Session)
        暂无编号
'''

from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'path': ''},
            {'path': 'druid/index.html'},
            {'path': 'druid/api.html'},
            {'path': 'index.html'},
            {'path': 'api.html'},
            # {'path': 'druid/datasource.html'},
            # {'path': 'druid/sql.html'},
            # {'path': 'druid/wall.html'},
            # {'path': 'druid/basic.json'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')                       # * Requests Client
        
        vul_info = {
            'app_name': 'AlibabaDruid',
            'vul_type': 'unAuthorized',
            'vul_id': 'alibaba-druid-unauth',
        }

        for payload in self.payloads:                    # * Payload
            path = payload['path']                              # * Path

            res = client.request(
                'get',
                path,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (
                (('Druid Stat Index' in res.text)
                    and ('druid.index' in res.text))
                or (('<title>Druid Stat JSON API</title>' in res.text) 
                    and ('druid.common' in res.text))
                # or (('<title>Druid DataSourceStat</title>' in res.text)
                #     and ('druid.datasource' in res.text))
                # or (('<title>Druid SQL Stat</title>' in res.text)
                #     and ('druid.sql' in res.text))
                # or (('<title>Druid DataSourceStat</title>' in res.text)
                #     and ('druid.wall' in res.text))
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
    