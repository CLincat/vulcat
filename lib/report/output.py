#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
from lib.initial.config import config
from lib.tool.timed import nowtime_year
from lib.tool.logger import logger
import json

def output_info(results, lang):
    logger.info('cyan_ex', lang['output']['info']['wait'])                              # ? 日志, 正在处理扫描结果
    results_info_list = []

    for result in results:
        if result:
            results_info = ''
            results_info += output_vul_info_color(result)
            results_info_list.append(results_info)
    results_info_list = set(results_info_list)                                          # * 去重

    if results_info_list:                                                                                                           # * 有漏洞   
        logger.info('green_ex', lang['output']['info']['vul'].format(logger.requests_number))              # ? 日志, 发现漏洞, 发送的请求包数量为xxx个
        for result in results_info_list:
            print(result, end='')
        logger.info('reset', '---', notime=True)                                                                                    # ? 结果, 重置文字颜色, 输出漏洞结果, 不显示时间
    else:                                                                                                                           # * 没有漏洞
        logger.info('red', lang['output']['info']['notvul'].format(logger.requests_number))                # ? 日志, 目标看起来没有漏洞, 发送的请求包数量为xxx个
    return None

def output_text(results, filename, lang):
    ''' 以txt格式保存扫描结果至文件中 '''
    try:
        f = open(filename, 'a')
        f.write('-'*50 + '\n' + '-'*5 + nowtime_year() + '\n')
        results_info_list = []

        for result in results:
            if result:
                results_info = '-----'
                results_info += output_vul_info(result)
                results_info_list.append(results_info)
        results_info_list = set(results_info_list)

        if results_info_list:  
            for result in results_info_list:
                f.write(result)
            logger.info('cyan_ex', lang['output']['text']['success'] + filename)        # ? 日志, 已保存结果至XXX.txt文件中
        f.close()
    except:
        logger.info('red_ex', lang['output']['text']['faild'])
    return None

def output_json(results, filename, lang):
    ''' 以json格式保存扫描结果至文件中 '''
    try:
        f = open(filename, 'a')
        f.write('-'*50 + '\n' + '-'*5 + nowtime_year() + '\n')
        results_info_list = []

        for result in results:
            if result:
                results_info = '-----\n'
                results_info += json.dumps(result) + '\n'
                results_info_list.append(results_info)
        results_info_list = set(results_info_list)

        if results_info_list:   
            for result in results_info_list:
                # result = result.replace('{', '{\n\t')
                # result = result.replace(', ', ',\n\t')
                f.write(result)
            logger.info('cyan_ex', lang['output']['json']['success'] + filename)        # ? 日志, 已保存结果至XXX.json文件中
        f.close()
    except:
        logger.info('red_ex', lang['output']['json']['faild'])
    return None

def output_html(result):
    ''' # ! 功能还没写好, 莫急莫急
    以html格式保存扫描结果至文件中
    '''
    pass

def output_vul_info_color(result):
    ''' 漏洞信息, 带颜色, 用于命令行输出 '''
    result_info = color.reset('\r---'.ljust(70) + '\n')
    for key, value in result.items():
        value_type = type(value)                                                        # * 保存value类型
        if value_type == str:                                                           # * str输出方式
            result_info += color.yellow_ex(key) + color.reset(': ' + value + '\n|    ')
        elif value_type == list:                                                        # * list输出方式
            result_info += color.yellow_ex(key) + color.reset(': ')
            for v in value:
                result_info += v + '  '
            result_info += '\n|    '
        elif value_type == dict:                                                        # * dict输出方式
            result_info += '\r|    ' + color.red_ex(key) + color.reset(':\t' + '\n')
            for k, v in value.items():
                result_info += '|        ' + color.yellow_ex(k) + color.reset(': ' + v + '\n')
    return result_info

def output_vul_info(result):
    ''' 漏洞信息, 无颜色, 用于保存结果至文件中 '''
    result_info = '\n'
    for key, value in result.items():
        value_type = type(value)
        if value_type == str:
            result_info += key + ': ' + value + '\n|    '
        elif value_type == list:
            result_info += key + ': '
            for v in value:
                result_info += v + '  '
            result_info += '\n|    '
        elif value_type == dict:
            result_info += key + ':\t' + '\n'
            for k, v in value.items():
                result_info += '|        ' + k +': ' + v + '\n'
    return result_info