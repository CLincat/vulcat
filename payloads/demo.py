#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    XXXXX扫描类: 
        XXXXX 未开启强制路由RCE
            CNVD-2018-24942
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Demo():
    ''' 标有感叹号!的都需要自己填写 '''
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = ''                              # ! 漏洞框架/应用程序/CMS等
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.!!!_payloads = [                           # ! 对应漏洞的Payload, 格式为: 漏洞编号_payloads, 例如cnvd_2018_24942_payloads
            {
                'path': '!!!',                          # ! 漏洞路径
                'data': ''                              # ! POST数据, 没有的话可以不写
            },
        ]

    def !!!_scan(self, url):                            # ! POC的名称, 格式为: 漏洞编号_scan, 例如cnvd_2018_24942_scan
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = '!!!'                    # ! 漏洞类型
        vul_info['vul_id'] = '!!!'                      # ! 漏洞编号
        vul_info['vul_method'] = '!!!'                  # ! 请求方式
        vul_info['headers'] = {}                        # ! 如果该漏洞需要特殊的Headers,如User-Agent:Nacos-Server, 则需要填写, 没有的话就不用填

        headers = self.headers
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.!!!_payloads:               # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.!!!(                     # ! 请求方式
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
            '''
            if ('!!!'):               # ! 判断扫描结果
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

    def addscan(self, url):
        return [
            # * thread(target=self.cnvd_2018_24942_scan, url=url),
            thread(target=self.!!!_scan, url=url)                  # ! POC的名称, 参考上一行
        ]

demo = Demo()