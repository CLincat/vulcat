#!/usr/bin/env /python3
# -*- coding:utf-8 -*-

'''
    检查
        无法连接至目标url
        连接目标url超时
        检查poc误报
            例如直接输出payload在页面中的情况
            参考: https://github.com/zhzyker/vulmap/blob/main/core/verify.py
'''

from lib.initial.config import config
from thirdparty import requests
import re

def check_connect(url):
    timeout = config.get('timeout')
    headers = config.get('headers')
    proxies = config.get('proxies')
    try:
        requests.get(
            url, 
            timeout=timeout, 
            headers=headers, 
            proxies=proxies, 
            verify=False,
            allow_redirects=False
        )

        return True
    except requests.ConnectTimeout:
        return False
    except requests.ConnectionError:
        return False
    except Exception as e:
        # print(e)
        return False

def check_res(res, md):
    ''' 检查poc误报
    来自: https://github.com/zhzyker/vulmap/blob/main/core/verify.py
    '''
    res_info = "echo.{0,20}" + md
    if(re.search(res_info, res) != None):
        return "not_vul"
    else:
        return res
