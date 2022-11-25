#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
import re

def cve_2018_1002015_scan(self, url):
    ''' ThinkPHP 5.0.23及5.1.31以下版本RCE
        ThinkPHP 5.0.x版本和5.1.x版本中存在远程代码执行漏洞, 
        该漏洞源于ThinkPHP在获取控制器名时未对用户提交的参数进行严格的过滤,
        远程攻击者可通过输入字符 \ 的方式调用任意方法利用该漏洞执行代码
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2018-1002015'
    vul_info['vul_method'] = 'POST'

    for payload in self.cve_2018_1002015_payloads:
        path = payload['path']
        data = payload['data']
        headers = payload['headers']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['headers'] = headers
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

            if (re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', res.text, re.I|re.M|re.S)
                or (self.md in check.check_res(res.text, self.md))
                or (('PHP Version' in res.text) 
                    and ('PHP License' in res.text))
            ):
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
