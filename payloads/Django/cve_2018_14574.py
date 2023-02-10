#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# from lib.tool import check

cve_2018_14574_payloads = [
    {'path': '/www.example.com'}
]

def cve_2018_14574_scan(self, clients):
    ''' 如果 django.middleware.common.CommonMiddleware和 APPEND_SLASH设置都已启用; 
        如果项目的 URL 模式接受任何以斜杠结尾的路径, 则对该站点的恶意制作的 URL 的请求可能会导致重定向到另一个站点; 
        从而启用网络钓鱼和其他攻击
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'Redirect',
        'vul_id': 'CVE-2018-14574',
    }

    for payload in cve_2018_14574_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (res.headers.get('Location')
            and ('//www.example.com/' in res.headers.get('Location', ''))
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
