#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from thirdparty import requests

def get_dnslog_cn_domain(self, sessid):
    headers = self.dnslog_cn_headers.copy()
    headers['Cookie'] = 'PHPSESSID=' + sessid
    res = requests.get(
        self.dnslog_cn_domain,
        timeout=self.timeout,
        headers=headers,
        verify=False
    )
    domain = res.text
    return domain

def get_dnslog_cn_result(self, md, sessid):
    headers = self.dnslog_cn_headers.copy()
    headers['Cookie'] = 'PHPSESSID=' + sessid
    res = requests.get(
        self.dnslog_cn_result,
        timeout=self.timeout,
        headers=headers,
        verify=False
    )
    if (md in res.text):
        return True             # * 无回显漏洞验证-成功
    else:
        return False            # * 无回显漏洞验证-失败
