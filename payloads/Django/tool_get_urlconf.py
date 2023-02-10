#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

def get_urlconf(self, client, vul_info):
    ''' 获取Django定义的URL路径 '''
    path = 'abcdefg'
    
    res = client.request(
        'get',
        path,
        allow_redirects=False,
        vul_info=vul_info
    )
    if res is None:
        return None
    
    urlConfList = None
    urlPatterns = re.search(r'<ol>.*</ol>', res.text, re.I|re.M|re.U|re.S)
    
    if urlPatterns:
        delete_strs = [' ', '\n', '^', '$', '<ol>', '</ol>', '<li>', 'logout/']  # * 用户名/logout/ 会清除当前用户登录状态, 所以要避免访问该路径
        
        urlConf = urlPatterns.group(0)
        for delete_str in delete_strs:                      # * 把无关字符 替换为空
            urlConf = urlConf.replace(delete_str, '')
        
        urlConfList = urlConf.split('</li>')                # * 根据</li>将每个路径分隔为列表
        urlConfList.pop(-1)                                 # * 删除最后一个 空字符串''
        
        for i in range(len(urlConfList)):
            urlPath = urlConfList[i]
            urlPathPatterns = re.search(r'\[.*\]', urlPath, re.I|re.M|re.U|re.S)
            
            if urlPathPatterns:                             # * 如果发现 [XXX] 无关字符, 则替换为空
                delete_str = urlPathPatterns.group(0)
                urlConfList[i] = urlPath.replace(delete_str, '').strip('/')
            else:
                urlConfList[i] = urlPath.strip('/')
    
    return urlConfList
