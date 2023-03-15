#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

def get_route_path(client, vul_info):
    ''' 获取Ruby on Rails的路径 '''
    new_routePathList = []
    
    res = client.request(
        'get',
        'abcdefg',
        allow_redirects=False,
        vul_info=vul_info
    )
    if res is None:
        return None
    
    s = re.compile(r"<td data-route-path='/.{1,200}\(\.:format\)'")
    routePathList = s.findall(res.text, re.I|re.M|re.S)

    if routePathList:
        for path in routePathList:
            path = path.replace("<td data-route-path='/", '')
            path = path.replace("(.:format)'", '')
            new_routePathList.append(path)

        new_routePathList.append('')        # * 空路径(当前路径)
        return new_routePathList
    else:
        return None
