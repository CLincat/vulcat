#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
import time as t

# def nowtime():
#     localtime = t.strftime('%H:%M:%S', t.localtime())
#     print(blue_ex('[{}] '.format(localtime)), end='')

def nowtime():
    ''' 返回当前时间(时:分:秒)'''
    localtime = t.strftime('%H:%M:%S', t.localtime())
    return color.blue_ex('[{}] '.format(localtime))

def nowtime_year():
    ''' 返回当前时间(年-月-日 时:分:秒)'''
    localtime_year = t.strftime('%Y-%m-%d %H:%M:%S', t.localtime())
    return localtime_year

def custom_time(timeFormat: str):
    ''' 自定义时间格式并返回 '''
    customTime = t.strftime(timeFormat, t.localtime())
    return customTime

def getTime():
    ''' 返回当前的时间戳, int类型 '''
    return int(t.time())
