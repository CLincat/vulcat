#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from thirdparty import HackRequests
from time import sleep
import re

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
            res = requests.10(                      # ! 10: 请求方式(例如 get)
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
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
        except requests.ConnectTimeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except requests.ConnectionError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None
