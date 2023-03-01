#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from thirdparty import requests

def get_ceye_domain(self):
    return self.ceye_domain


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
