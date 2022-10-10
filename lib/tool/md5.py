#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    获取md5值, 取前6位
    获取随机的md5值, 取前8位
'''

import hashlib
import random

def md5(app_name):
    ''' 生成md5值, 并返回前6位 '''
    md = hashlib.md5()
    md.update(app_name.encode('utf-8'))
    
    return md.hexdigest()[:6]

def random_md5():
    random_number = str(random.randint(0, 99999999))
    md = hashlib.md5()
    md.update(random_number.encode('utf-8'))

    return md.hexdigest()[:8]

def random_int_1():
    ''' 返回1个随机整数, 范围1234-5678 '''
    num1 = random.randint(1234, 5678)
    return num1

def random_int_2():
    ''' 返回2个随机整数, 范围1234-5678 '''
    num1 = random.randint(1234, 5678)
    num2 = random.randint(1234, 5678)

    return num1, num2