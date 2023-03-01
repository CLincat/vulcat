#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from thirdparty import requests

def get_dnslog_pw_domain(self):
    return self.dnslog_pw_domain

def get_dnslog_pw_result(self, md):
    domains = self.dnslog_pw_domain.split('.')  # * 分隔域名
    username = domains[-3]                          # * 获取域名中的 用户名 部分
    
    pw_result = self.dnslog_pw_result.format(
        username=username,
        prefix=self.pw_random_prefix,
        token=self.dnslog_pw_token
    )
    
    res = requests.get(
        pw_result,
        timeout=self.timeout,
        verify=False
    )
    
    # * 存在记录则dnslog.pw会返回True
    # * 不存在则返回False
    if (md in res.text):
        return True                 # * 无回显漏洞验证-成功
    else:
        return False                # * 无回显漏洞验证-失败
