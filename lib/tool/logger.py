#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.initial.config import config
from lib.tool.timed import nowtime
from lib.tool import color
from thirdparty.tqdm import tqdm

class Logger():
    def __init__(self):
        self.requests_number = 0                                    # * http请求计数

    def info(self, text_color, text, notime=False, print_end='\n'):
        text = text.replace('\\', '\\\\')                           # * 防止eval时字符被转义
        command = 'color.{}("{}")'.format(text_color, text)         # * 颜色 + 文字
        now_time = '' if notime else nowtime()                      # * 是否显示时间

        tqdm.write(now_time + eval(command), end=print_end)

    def logging(self, vul_info):
        self.requests_number += 1                                   # * http请求数加1
        log_level = config.get('log')                               # * 获取日志等级

        if (log_level > 1) and (log_level <= 3):
            log_function = 'self.logging_{}({})'.format(
                log_level,
                vul_info
            )
            log_info = eval(log_function)
            tqdm.write((nowtime() + log_info + color.yellow_ex('')).ljust(140))

    def logging_0(self, *args):
        ''' 功能尚未完成, 还在写 '''
        pass

    def logging_1(self, *args):
        ''' 功能尚未完成, 还在写 '''
        pass

    def logging_2(self, vul_info):
        ''' 日志2级, 框架名称+漏洞编号+状态码'''
        info_2 = color.red_ex('[LOG-{}-{}]'.format(vul_info['app_name'], str(self.requests_number)))
        info_2 += color.red_ex(' [') + color.magenta_ex(vul_info['status_code']) + color.red_ex(']')
        info_2 += color.red_ex(' [') + color.black_ex(vul_info['vul_id']) + color.red_ex(']')

        return info_2

    def logging_3(self, vul_info):
        ''' 日志3级, (框架名称+漏洞编号+状态码)+请求方法+请求目标+POST数据 '''
        info_3 = self.logging_2(vul_info)

        info_3 += color.red_ex(' [' + vul_info['vul_method'] + ' ')
        info_3 +=color.black_ex(vul_info['target']) + color.red_ex(']')
        if vul_info['data']:
            info_3 += color.red_ex(' [DATA ') + color.black_ex(vul_info['data']) + color.red_ex(']')

        return info_3

    def logging_4(self, *args):
        ''' 功能尚未完成, 还在写 '''
        pass

    def logging_5(self):
        ''' 功能尚未完成, 还在写 '''
        pass

    def logging_6(self):
        ''' 功能尚未完成, 还在写 '''
        pass

logger = Logger()