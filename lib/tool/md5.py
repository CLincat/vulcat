#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    md5
'''

import hashlib
import random

def md5(app_name, num=6):
    ''' 生成md5值, 默认返回前6位, 最大32 '''
    md = hashlib.md5()
    md.update(app_name.encode('utf-8'))
    
    return md.hexdigest()[:num]

def random_md5():
    random_number = str(random.randint(0, 99999999))
    md = hashlib.md5()
    md.update(random_number.encode('utf-8'))

    return md.hexdigest()[:8]

def random_int_1(len = 4):
    ''' 返回1个随机整数, 默认范围1234-5678
            @param len
                随机数长度, 默认为4, 最小为1, 最大为6
            范围
                1-9
                10-99
                100-999
                1234-5678
                12345-56789
                123456-567890
    '''

    num_list_1 = [0, 1, 10, 100, 1234, 12345, 123456]
    num_list_2 = [0, 9, 99, 999, 5678, 56789, 567890]
    
    num1 = random.randint(num_list_1[len], num_list_2[len])

    return num1

def random_int_2(len = 4):
    ''' 返回2个随机整数, 默认范围1234-5678
            @param len
                随机数长度, 默认为4, 最小为1, 最大为6
            范围
                1-9
                10-99
                100-999
                1234-5678
                12345-56789
                123456-567890
    '''

    num_list_1 = [0, 1, 10, 100, 1234, 12345, 123456]
    num_list_2 = [0, 9, 99, 999, 5678, 56789, 567890]

    num1 = random.randint(num_list_1[len], num_list_2[len])
    num2 = random.randint(num_list_1[len], num_list_2[len])

    return num1, num2