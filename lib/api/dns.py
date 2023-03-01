#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    配合dnslog.cn, ceye.io等平台进行漏洞验证, 目前支持:
        www.dnslog.cn
        dnslog.pw
        ceye.io
'''

from lib.tool.md5 import random_md5
from lib.initial.config import config
from lib.api.dnslog_cn import *
from lib.api.dnslog_pw import *
from lib.api.ceye_io import *

class DNS():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.dns_platform = config.get('dns')               # * 获取使用的dns平台, 默认为auto自动
        if self.dns_platform == 'auto':
            self.dns_platform = 'ceye/dnslog-pw/dnslog-cn'

        # * http://dnslog.cn
        self.dnslog_cn_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',
            'Accept': '*/*',
            'Cookie': 'PHPSESSID=md5sessionid'
        }
        self.dnslog_cn_domain = 'http://www.dnslog.cn/getdomain.php?t=0.147852369134679258'
        self.dnslog_cn_result = 'http://www.dnslog.cn/getrecords.php?t=0.147852369134679258'

        # * http://ceye.io
        self.ceye_domain = config.get('ceye_domain')
        self.ceye_token = config.get('ceye_token')
        self.ceye_result = 'http://api.ceye.io/v1/records?token={}&type=dns&filter='.format(self.ceye_token)

        # * http://dnslog.pw
        self.pw_random_prefix = random_md5(4)
        self.dnslog_pw_domain = self.pw_random_prefix + '.' + config.get('dnslog_pw_domain')
        self.dnslog_pw_token = config.get('dnslog_pw_token')
        # self.dnslog_pw_result = 'http://dnslog.pw/api/dns/{username}/{prefix}/?token={token}'
        self.dnslog_pw_result = 'http://dnslog.pw/api/group/dns/{username}/{prefix}/?token={token}'

    # * 获取域名
    def domain(self, sessid):
        try:
            if (('ceye' in self.dns_platform) and (self.ceye_domain) and (self.ceye_token)):
                return self.get_ceye_domain()
            elif (('dnslog-pw' in self.dns_platform) and (self.dnslog_pw_domain) and (self.dnslog_pw_token)):
                return self.get_dnslog_pw_domain()
            elif ('dnslog-cn' in self.dns_platform):
                return self.get_dnslog_cn_domain(sessid)
            else:
                return 'NotDns'
        except:
            return 'dnslogGetError'

    def result(self, md, sessid):
        try:
            if (('ceye' in self.dns_platform) and (self.ceye_domain)):
                return self.get_ceye_result(md)
            elif (('dnslog-pw' in self.dns_platform) and (self.dnslog_pw_domain)):
                return self.get_dnslog_pw_result(md)
            elif ('dnslog-cn' in self.dns_platform):
                return self.get_dnslog_cn_result(md, sessid)
            else:
                return False                # * 没有结果
        except:
            return False                    # * 连接 DNSLOG平台时发生错误

DNS.get_dnslog_cn_domain = get_dnslog_cn_domain
DNS.get_dnslog_cn_result = get_dnslog_cn_result

DNS.get_dnslog_pw_domain = get_dnslog_pw_domain
DNS.get_dnslog_pw_result = get_dnslog_pw_result

DNS.get_ceye_domain = get_ceye_domain
DNS.get_ceye_result = get_ceye_result

dns = DNS()