#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2020_3580_scan(self, url):
    ''' Cisco ASA设备/FTD设备 XSS跨站脚本攻击
            反射型
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'XSS'
    vul_info['vul_id'] = 'CVE-2020-3580'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {}

    headers = self.headers
    headers.update(vul_info['headers'])

    for payload in self.cve_2020_3580_payloads:     # * Payload
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
            logger.logging(vul_info, res.status_code, res)                        # * LOG


            # todo 判断
            if (("onload=confirm('" + str(self.random_num) + "')") in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': res
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
