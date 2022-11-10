#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    XXXXX扫描类: 
        XXXXX 未开启强制路由RCE
            CNVD-2018-24942
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
from thirdparty import HackRequests
from time import sleep
import socket

class 1():                                              # ! 1: 类名(例如 ThinkPHP)
    ''' 标有数字的地方都需要自己填写 '''
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')
        self.proxy = config.get('proxy')

        self.app_name = '2'                             # ! 2: 漏洞框架/应用程序/CMS等(例如 thinkphp)
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.3_payloads = [                             # ! 3: Payload的名称(例如 cnvd_2018_24942_payloads)
            {
                'path': '4',                            # ! 4: url路径(例如/admin/login)
                'data': '5'                             # ! 5: POST数据, 没有的话可以不写
            },
        ]

    def 6_scan(self, url):                              # ! 6: POC的名称(例如 cnvd_2018_24942_scan)
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = '7'                      # ! 7: 漏洞类型(例如 RCE)
        vul_info['vul_id'] = '8'                        # ! 8: 漏洞编号(例如 CNVD-2018-24942)
        vul_info['vul_method'] = '9'                    # ! 9: 请求方式(例如 GET)
        vul_info['headers'] = {}                        # ! 如果该漏洞需要特殊的Headers,例如 User-Agent:Nacos-Server, 则需要填写, 没有的话就不用填

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.3_payloads:                 # ! 3: 同上, Payload的名称
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                hack = HackRequests.hackRequests()
                
                res = hack.http(
                    target, 
                    method='10',                      # ! 10: 请求方式: GET/POST/HEAD
                    data=data, 
                    # timeout=self.timeout,          不支持超时
                    headers=headers,
                    proxy=self.proxy, 
                    location=False
                )
                res.method = '10'                     # ! 10: 同上, 请求方式
                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except socket.timeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except ConnectionRefusedError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            '''!!!
                可以自定义results中的信息, 格式:
                    标题: 值(str/list/dict)
                        str类型: key: value的格式进行显示
                        list类型: 会以key: value value value ...的格式进行显示
                        dict类型: 会以↓的格式进行显示
                                dict:
                                    key1: value1
                                    key2: value2
                                    ...
                        Response类型: 会以一个http数据包的格式进行显示
            '''
            if ('11'):               # ! 11: 判断扫描结果
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Headers': headers,
                        'Cookie': 'XXX'
                    },
                    'Request': res                  # * 会输出一个http数据包
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.6_scan, url=url)                  # ! 6: 同上, POC的名称
        ]

12 = 1()                                                         # ! 1: 同上, 类名

'''
    # ! 12: 对象名称
    # ! 需要在vulcat/lib/initial/config.py加入对象名称, 找到以下代码并继续添加
                                                        app_list = ['alidruid', 'airflow', 'apisix', 'cisco', 'django', 'fastjson']
    # ! 然后在vulcat/lib/core/coreScan.py引入POC, 引入方式为
                                                        from payloads.文件名 import 对象名称
    # ! 引入完成后, 自定义POC就成功了, 可以运行vulcat试试效果
'''