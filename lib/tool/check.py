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
import re

def check_connect(client):
    info = {
        'app_name': 'Check',
        'vul_id': 'check-connection'
    }
    
    res = client.request(
        'get',
        '',
        allow_redirects=False,
        vul_info=info
    )
    if res is None:
        return False

    return True

def check_res(resText, md, command='echo'):
    ''' 检查RCE-poc误报
    来自: https://github.com/zhzyker/vulmap/blob/main/core/verify.py
    '''
    res_info = command + ".{1,20}" + md
    
    if(re.search(res_info, resText) != None):
        return False            # * 回显异常, 误报
    else:
        if (md in resText):
            return True         # * 正确回显, 存在漏洞
        else:
            return False        # * 错误回显, 不存在漏洞

def check_res_fileread(resText, resHeaders=None):
    ''' 检查回显, 判断是否存在 FileRead(任意文件读取) 漏洞
        :param resText: 响应文本Response.text
        :param resHeaders(可选参数): 响应头, 有时候回显可能在 响应Headers 里 而不在 响应Body 里
        
        * /etc/passwd
            r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root'
        * C:/Windows/System32/drivers/etc/hosts
            'Microsoft Corp' and 'Microsoft TCP/IP for Windows'
    '''

    if (
        re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', resText, re.I|re.M|re.S)
        or (('Microsoft Corp' in resText) 
            and ('Microsoft TCP/IP for Windows' in resText))
    ):
        return True         # * 文件回显在 响应Body里, 存在FileRead漏洞
    elif (
        re.search(r'root:(x{1}|.*):\d{1,7}:\d{1,7}:root', str(resHeaders), re.I|re.M|re.S)
        or (('Microsoft Corp' in str(resHeaders)) 
            and ('Microsoft TCP/IP for Windows' in str(resHeaders)))
    ):
        return True         # * 文件回显在 响应Headers里, 存在FileRead漏洞
    
    return False            # * 没有找到文件回显, 不存在FileRead漏洞
