#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def alibaba_druid_unauthorized_scan(self, url):
    ''' druid未授权访问漏洞
            攻击者可利用druid管理面板, 查看Session信息, 并利用泄露的Session登录后台(有时候可能没有Session)
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_id'] = 'druid-unauth'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}
    
    headers = self.headers
    headers.update(vul_info['headers'])

    for payload in self.alibaba_druid_unauthorized_payloads: # * Payload
        path = payload['path']                               # * Path
        data = payload['data']                               # * Data
        target = url + path                                  # * Target

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


            # todo 判断
            if ('Stat Index' in res.text):
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
        except requests.ConnectTimeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except requests.ConnectionError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None
