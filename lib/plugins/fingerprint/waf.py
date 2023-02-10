#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    web应用程序防火墙 指纹识别
        参考-1: https://mp.weixin.qq.com/s/8F060FU9g_78z57UKS-JsQ
'''

from lib.initial.config import config
from lib.tool.logger import logger
from time import sleep
import re

class WafIdentify():
    def identify(self, client):
        '''
            waf识别
        '''
        try:
            vul_info = {
                'app_name': 'Waf',
                'vul_id': 'identify'
            }

            errors = {
                'Timeout': {
                    'text_color': 'red_ex',
                    'text': self.lang['core']['waf_finger']['Timeout']
                },
                'Faild': {
                    'text_color': 'red_ex',
                    'text': self.lang['core']['waf_finger']['Faild']
                },
                'Error': {
                    'text_color': 'red_ex',
                    'text': self.lang['core']['waf_finger']['Error']
                }
            }

            waf_info = None
            path_1 = '?id=1 and 1=1 -- qwe'
            path_2 = '?id=1\'"><iMg SrC=1 oNeRrOr=alert(1)>//'

            logger.info('yellow_ex', self.lang['core']['waf_finger']['start'])

            res = client.request(
                'get',
                path_2,
                vul_info=vul_info,
                errors=errors
            )

            if res is not None:
                res.encoding = 'utf-8'
                for waf_fp in self.waf_finger:
                    if (waf_info):
                        # * 如果已经识别出WAF, 则停止
                        break
                    
                    for finger in waf_fp['fingerprint']:
                        # if ((res.status_code == waf_fp['status_code']) and (finger in res.text)):
                        if (finger in res.text):
                            waf_info = waf_fp['name']
                            break

                if waf_info:
                    while True:
                        if (not self.batch):                                                            # * 是否使用默认选项
                            logger.info('red', '', print_end='')
                            operation = input(self.lang['core']['waf_finger']['Find'].format(waf_info))       # * 接收参数
                        else:
                            logger.info('red', self.lang['core']['waf_finger']['Find'].format(waf_info), print_end='')
                            operation = 'no'                                                            # * 默认选项No
                            logger.info('red', 'no', notime=True)

                        operation = operation.lower()                                                   # * 字母转小写
                        if operation in ['y', 'yes']:                                                   # * 继续扫描
                            logger.info('yellow_ex', self.lang['core']['stop']['continue'])             # ? 日志, 继续扫描
                            waf_info = 'yes'                                                            # ? 不听劝, 继续扫描
                            break
                        elif operation in ['n', 'no']:
                            logger.info('yellow_ex', self.lang['core']['stop']['next'])                 # ? 日志, 下一个
                            waf_info = 'no'                                                             # ? 有WAF, 不扫了不扫了, 换下一个URL
                            break
                else:
                    logger.info('yellow_ex', self.lang['core']['waf_finger']['NotFind'])

            return waf_info
        except:
            return waf_info

    def __init__(self):
        self.delay = config.get('delay')
        self.lang = config.get('lang')
        self.batch = config.get('batch')

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
                        '<h1 class="err">很抱歉，您提交的请求存在异常，请向网站管理员确认并获取正确的访问方式</h1>',
                        # '<link rel="stylesheet" href="https://imgcache.qq.com/qcloud/security/static/404style.css">',
                        # '<h1 class="err">很抱歉，您提交的请求存在异常，请向网站管理员确认并获取正确的访问方式</h1>',
                        # '<p class="text1">本页面为<span class="text-color">腾讯T-Sec Web应用防火墙(WAF)</span>默认提示页面，如有疑问请联系网站管理员</p>',
                        # '<title>Client Bad Request</title>',
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
                    'name': '百度云盾(BaiDu WAF)',
                    'status_code': 403,
                    'fingerprint': [
                        '如果您是网站管理员，点击查看<a href="https://su.baidu.com/" target="_blank">如何修复',
                        '<a href="http://anquan.baidu.com/bbs/forum.php?mod=viewthread&tid=371363&page=1&extra=" target="_blank">帮助支持</a>',
                        '<h1>403<small>当前访问可能造成安全威胁，您的访问被阻断。 攻击类型:【应用程序漏洞攻击】</small></h1>',
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