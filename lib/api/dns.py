#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    配合dnslog.cn, ceye.io等平台进行漏洞验证, 目前支持:
        www.dnslog.cn
        ceye.io
后续会改进dnslog.cn
'''

from lib.initial.config import config
from thirdparty import requests

class DNS():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.dns_platform = config.get('dns')               # * 获取使用的dns平台, 默认为all全部

        self.dnslog_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',
            'Accept': '*/*',
            'Cookie': 'PHPSESSID=md5sessionid'
        }
        self.dnslog_domain = 'http://www.dnslog.cn/getdomain.php?t=0.147852369134679258'
        self.dnslog_result = 'http://www.dnslog.cn/getrecords.php?t=0.147852369134679258'

        self.ceye_domain = config.get('ceye_domain')
        self.ceye_token = config.get('ceye_token')
        self.ceye_result = 'http://api.ceye.io/v1/records?token={}&type=dns&filter='.format(self.ceye_token)

    # * 获取域名
    def domain(self, sessid):
        try:
            if (('ceye' in self.dns_platform) and (self.ceye_domain)):
                return self.get_ceye_domain()
            elif ('dnslog' in self.dns_platform):
                return self.get_dnslog_domain(sessid)
            else:
                return 'NotDns'
        except requests.ConnectTimeout:
            return 'dnslog_timeout'
        except requests.ConnectionError:
            return 'dnslog_error'
        except Exception as e:
            # print(e)
            return 'dnslog_error'

    def result(self, md, sessid):
        try:
            if (('ceye' in self.dns_platform) and (self.ceye_domain)):
                return self.get_ceye_result(md)
            elif ('dnslog' in self.dns_platform):
                return self.get_dnslog_result(md, sessid)
            else:
                return False                # * 没有结果
        except requests.ConnectTimeout:
            return False                    # * 连接 DNSLOG平台 超时
        except requests.ConnectionError:
            return False                    # * 无法连接到 DNSLOG平台
        except Exception as e:
            # print(e)
            return False                    # * 连接 DNSLOG平台时发生致命错误

    # * 不同的dns平台
    def get_dnslog_domain(self, sessid):
        headers = self.dnslog_headers.copy()
        headers['Cookie'] = 'PHPSESSID=' + sessid
        res = requests.get(
            self.dnslog_domain,
            timeout=self.timeout,
            headers=headers,
            verify=False
        )
        domain = res.text
        return domain

    def get_ceye_domain(self):
        return self.ceye_domain

    # * 获取结果
    def get_dnslog_result(self, md, sessid):
        headers = self.dnslog_headers.copy()
        headers['Cookie'] = 'PHPSESSID=' + sessid
        res = requests.get(
            self.dnslog_result,
            timeout=self.timeout,
            headers=headers,
            verify=False
        )
        if (md in res.text):
            return True             # * 无回显漏洞验证-成功
        else:
            return False            # * 无回显漏洞验证-失败

    def get_ceye_result(self, md):
        res = requests.get(
            self.ceye_result + md,
            timeout=self.timeout,
            verify=False
        )
        if (md in res.text):
            return True             # * 无回显漏洞验证-成功
        else:
            return False            # * 无回显漏洞验证-失败

dns = DNS()