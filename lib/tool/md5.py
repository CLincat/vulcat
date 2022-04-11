#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    获取md5值, 取前6位
'''

import hashlib

def md5(app_name):
    ''' 生成md5值, 并返回前6位 '''
    md = hashlib.md5()
    md.update(app_name.encode('utf-8'))
    
    return md.hexdigest()[:6]