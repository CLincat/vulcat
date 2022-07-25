#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.initial.config import config
from lib.tool.timed import nowtime
from lib.tool import color
from thirdparty.tqdm import tqdm
import http.client

class Logger():
    def __init__(self):
        self.requests_number = 0                                    # * http请求计数

    def info(self, text_color, text, notime=False, print_end='\n'):
        text = text.replace('\\', '\\\\')                           # * 防止eval时字符被转义
        command = 'color.{}("{}")'.format(text_color, text)         # * 颜色 + 文字
        now_time = '' if notime else nowtime()                      # * 是否显示时间

        tqdm.write(now_time + eval(command), end=print_end)

    def logging(self, vul_info, status_code, res=None):
        self.requests_number += 1                                   # * http请求数加1
        log_level = config.get('log')                               # * 获取日志等级

        if (log_level > 1) and (log_level <= 6):
            log_function = 'self.logging_{}(vul_info, status_code, res)'.format(log_level)
            log_info = eval(log_function)
            tqdm.write((nowtime() + log_info + color.yellow_ex('')).ljust(140))

    def logging_0(self, *args):
        ''' 功能尚未完成, 还在写 '''
        pass

    def logging_1(self, *args):
        ''' 功能尚未完成, 还在写 '''
        pass

    def logging_2(self, vul_info, status_code, *args):
        ''' 日志2级, 框架名称+状态码+漏洞编号'''
        info_2 = color.red_ex('[LOG-{}-{}]'.format(str(self.requests_number), vul_info['app_name']))
        info_2 += color.red_ex(' [') + color.magenta_ex(str(status_code)) + color.red_ex(']')
        info_2 += color.red_ex(' [') + color.black_ex(vul_info['vul_id']) + color.red_ex(']')

        return info_2

    def logging_3(self, vul_info, status_code, res):
        ''' 日志3级, (框架名称+状态码+漏洞编号)+请求方法+请求目标+POST数据 '''
        info_3 = self.logging_2(vul_info, status_code)

        try:
            info_3 += color.red_ex(' [' + res.request.method + ' ')
            info_3 +=color.black_ex(res.request.url) + color.red_ex(']')
            if vul_info['data']:
                info_3 += color.red_ex(' [DATA ') + color.black_ex(res.request.body) + color.red_ex(']')
        except:
            return info_3

        return info_3

    def logging_4(self, vul_info, status_code, res):
        ''' 日志4级, (框架名称+状态码+漏洞编号)+请求数据包 '''
        info_4 = self.logging_2(vul_info, status_code)
        try:
            info_4 += color.red_ex(' [Request')
            info_4 += color.black_ex('\n' + res.request.method + ' ' + res.request.path_url + ' ' + http.client.HTTPConnection._http_vsn_str)
            info_4 += color.black_ex('\n' + 'Host' + ': ' + self.get_domain(res.request.url))

            for key, value in res.request.headers.items():
                info_4 += color.black_ex('\n' + key + ': ' + value)
            if res.request.body:
                info_4 += color.black_ex('\n\n' + res.request.body)

            info_4 += color.red_ex('\n]')
            info_4 += color.reset('')
        except:
            return info_4
        return info_4

    def logging_5(self, vul_info, status_code, res):
        ''' 日志5级, (框架名称+状态码+漏洞编号)+请求包+响应头 '''
        info_5 = self.logging_4(vul_info, status_code, res)
        try:
            info_5 += color.red_ex(' [Response')

            for key, value in res.headers.items():
                info_5 += color.black_ex('\n' + key + ': ' + value)

            info_5 += color.red_ex('\n]')
        except:
            return info_5
        return info_5

    def logging_6(self, vul_info, status_code, res):
        ''' 日志6级, (框架名称+状态码+漏洞编号)+请求包+响应头+响应内容 '''
        res.encoding = 'utf-8'
        info_6 = self.logging_5(vul_info, status_code, res)
        try:
            info_6 = info_6[:-1]
            info_6 += color.black_ex('\n\n' + res.text)

            info_6 += color.red_ex('\n]')
        except:
            return info_6
        return info_6

    def get_domain(self, url):
        try:
            start_index = url.find('//')
            if start_index:
                start_index += 2
            else:
                return 'None'
            end_index = url.find('/', start_index)
            domain = url[start_index:end_index]
            return domain
        except:
            return 'Error'

logger = Logger()