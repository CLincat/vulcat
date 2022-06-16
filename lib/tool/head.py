#!/usr/bin/env /python3
# -*- coding:utf-8 -*-

'''
    Headers请求头处理
        合并2个headers
'''

def merge(old_headers, new_headers):
    '''
        用于合并2个headers, 并返回合并后的headers, 新headers将会覆盖旧headers中的同名内容.
    '''

    merge_headers = old_headers.copy()
    merge_headers.update(new_headers)
    return merge_headers