#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    web应用程序防火墙 指纹识别
        参考-1: https://mp.weixin.qq.com/s/8F060FU9g_78z57UKS-JsQ
'''

from lib.initial.config import config
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

class WafIdentify():
    def identify(self, url):
        '''
            waf识别
        '''
        try:
            vul_info = {
                'app_name': 'Waf',
                'vul_id': 'identify'
            }
            path_1 = '?id=1 and 1=1 -- qwe'
            path_2 = '?id=1\'"><iMg SrC=1 oNeRrOr=alert(1)>//'

            url_1 = url + path_1
            url_2 = url + path_2

            logger.info('yellow_ex', self.lang['core']['waf_finger']['waf'])

            res = requests.get(
                url_2,
                timeout=self.timeout,
                headers=self.headers,
                proxies=self.proxies,
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG

            res.encoding = 'utf-8'
            for waf_fp in self.waf_finger:
                for finger in waf_fp['fingerprint']:
                    # if ((res.status_code == waf_fp['status_code']) and (finger in res.text)):
                    if (finger in res.text):
                        return waf_fp['name']

            return None
        except requests.ConnectTimeout:
            logger.info('red_ex', self.lang['core']['waf_finger']['waf_timeout'])
            return None
        except requests.ConnectionError:
            logger.info('red_ex', self.lang['core']['waf_finger']['waf_conn_error'])
            return None
        except:
            logger.info('red_ex', self.lang['core']['waf_finger']['waf_error'])
            return None


    def __init__(self):
        self.delay = config.get('delay')
        self.lang = config.get('lang')
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        # * waf指纹库
        self.waf_finger = [
                {
                    'name': '阿里云盾(Aliyun Waf)',
                    'status_code': 405,
                    'fingerprint': [
                        '很抱歉，由于您访问的URL有可能对网站造成安全威胁，您的访问被阻断',
                        'your request has been blocked as it may cause potential threats to the server'
                    ]
                },
                {
                    'name': '腾讯云盾(Tencent WAF)',
                    'status_code': 403,
                    'fingerprint': [
                        '腾讯T-Sec Web应用防火墙(WAF)',
                        # '很抱歉，您提交的请求可能对网站造成威胁，请求已被管理员设置的策略阻断'
                    ]
                },
                {
                    'name': '安全狗(SafeDog)',
                    'status_code': None,
                    'fingerprint': [
                        '如果您是网站管理员，请登录安全狗',
                        '您的请求带有不合法参数，已被网站管理员设置拦截'
                    ]
                },
                {
                    'name': '华为云盾(HuaWei WAF)',
                    'status_code': 418,
                    'fingerprint': [
                        '您的请求疑似攻击行为'
                    ]
                },
                {
                    'name': '网宿云盾',
                    'status_code': None,
                    'fingerprint': [
                        '您当前的访问行为存在异常，请稍后重试'
                    ]
                },
                {
                    'name': '创宇盾',
                    'status_code': None,
                    'fingerprint': [
                        '当前访问疑似黑客攻击，已被创宇盾拦截',
                        '最近有可疑的攻击行为，请稍后重试'
                    ]
                },
                {
                    'name': '玄武盾',
                    'status_code': None,
                    'fingerprint': [
                        '您的访问可能对网站造成危险，已被云防护安全拦截'
                    ]
                },
                # {
                #     'name': '360网站卫士',
                #     'status_code': None,
                #     'fingerprint': [
                #         '当前访问可能对网站安全造成威胁，已被网站卫士拦截'
                #     ]
                # },
                # {
                #     'name': '奇安信网站卫士 ',
                #     'status_code': 493,
                #     'fingerprint': [
                #         '抱歉！您的访问可能对网站造成威胁，已被云防护拦截'
                #     ]
                # }, 
                {
                    'name': '长亭SafeLine',
                    'status_code': 403,
                    'fingerprint': [
                        '您的访问请求可能对网站造成安全威胁，请求已被 长亭 SafeLine 阻断'
                    ]
                },
                {
                    'name': 'OpenRASP',
                    'status_code': 400,
                    'fingerprint': [
                        'Request blocked by OpenRASP',
                        '您的请求包含恶意行为，已被服务器拒绝'
                    ]
                },
                {
                    'name': '西部数码云网盾',
                    'status_code': None,
                    'fingerprint': [
                        '检测到疑似攻击行为，访问已被云网盾拦截',
                        '系统检查到您的访问存在疑似攻击的行为，已经自动列入禁止名单'
                    ]
                },
                {
                    'name': '云WAF(waf种类暂时未知)',
                    'status_code': 461,
                    'fingerprint': [
                        '请求被WEB防火墙拦截'
                    ]
                }
                # {
                #     'name': '',
                #     'status_code': 403,
                #     'fingerprint': [
                #         ''
                #     ]
                # }
            ]

waf = WafIdentify()