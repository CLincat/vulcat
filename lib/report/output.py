#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
from lib.initial.config import config
from lib.tool.timed import nowtime_year
from lib.tool.logger import logger
from thirdparty import requests
from thirdparty import HackRequests
# from lib.plugins.Exp import exp
import json
import http.client

def output_info(results, lang):
    # cmd = config.get('command')
    
    logger.info('cyan_ex', lang['output']['info']['wait'])                              # ? 日志, 正在处理扫描结果
    results_info_list = []

    for result in results:
        # if (result and cmd):
            # exp(result)
        if result:
            results_info = ''
            results_info += output_vul_info_color(result)
            results_info_list.append(results_info)
    results_info_list = set(results_info_list)                                          # * 去重

    if results_info_list:                                                                                                           # * 有漏洞   
        logger.info('red_ex', lang['output']['info']['vul'].format(logger.requests_number))              # ? 日志, 发现漏洞, 发送的请求包数量为xxx个
        for result in results_info_list:
            print(result, end='')
        logger.info('reset', '---', notime=True)                                                                                    # ? 结果, 重置文字颜色, 输出漏洞结果, 不显示时间
    else:                                                                                                                           # * 没有漏洞
        logger.info('green_ex', lang['output']['info']['notvul'].format(logger.requests_number))                # ? 日志, 目标看起来没有漏洞, 发送的请求包数量为xxx个
    return None

def output_text(results, filename, lang):
    ''' 以txt格式保存扫描结果至文件中 '''
    try:
        results_info_list = []

        for result in results:
            if result:
                f = open(filename, 'a')
                f.write('-'*50 + '\n' + '-'*5 + nowtime_year() + '\n')

                results_info = '-----'
                results_info += output_vul_info(result)
                results_info_list.append(results_info)
        results_info_list = set(results_info_list)

        if results_info_list:  
            for result in results_info_list:
                f.write(result)
            logger.info('cyan_ex', lang['output']['text']['success'] + filename)        # ? 日志, 已保存结果至XXX.txt文件中
        else:
            logger.info('cyan_ex', lang['output']['text']['notvul'] + filename)        # ? 日志, 没有漏洞, 未生成文件
            return None
        f.close()
    except:
        logger.info('red_ex', lang['output']['text']['faild'])
    return None

def output_json(results, filename, lang):
    ''' 以json格式保存扫描结果至文件中 
        :param results: POC返回的漏洞信息, 字典类型
        :param filename: 保存的文件名
        :param lang: 语言
    '''
    try:
        results_info_list = []

        for result in results:
            if result:
                f = open(filename, 'a')

                result_info = {
                    'Time': nowtime_year()
                }
                result_info.update(result)

                # * Response对象不能json化, 转为字符串
                for key in result_info.keys():
                    if type(result_info[key]) == requests.models.Response:
                        result_info[key] = output_res(key, result_info[key], iscolor=False)
                    elif type(result_info[key]) == HackRequests.response:
                        result_info[key] = output_Hackres(key, result_info[key], iscolor=False) 

                results_info_list.append(json.dumps(result_info, indent=4) + '\n')
        results_info_list = set(results_info_list)

        if results_info_list:   
            for result in results_info_list:
                # result = result.replace('{', '{\n\t')
                # result = result.replace(', ', ',\n\t')
                f.write(result)
            logger.info('cyan_ex', lang['output']['json']['success'] + filename)        # ? 日志, 已保存结果至XXX.json文件中
        else:
            logger.info('cyan_ex', lang['output']['json']['notvul'] + filename)         # ? 日志, 没有漏洞, 未生成文件
            return None
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
    ''' 漏洞信息, 带颜色, 用于命令行输出
        :param result: POC返回的漏洞信息, 字典类型
    '''
    result_info = color.reset('\r---'.ljust(70) + '\n')
    for key, value in result.items():
        value_type = type(value)                                                        # * 保存value类型

        if value_type == str:                                                           # * str输出方式
            result_info += output_str(key, value)

        elif value_type == list:                                                        # * list输出方式
            result_info += output_list(key, value)

        elif value_type == dict:                                                        # * dict输出方式
            result_info += output_dict(key, value)

        elif value_type == requests.models.Response:                                    # * Response输出方式
            result_info += output_res(key, value)

        elif value_type == HackRequests.response:
            result_info += output_Hackres(key, value)                                   # * HackResponse输出方式

    return result_info

def output_vul_info(result):
    ''' 漏洞信息, 无颜色, 用于保存结果至文件中 '''
    result_info = '\n'
    for key, value in result.items():
        value_type = type(value)
        if value_type == str:
            result_info += output_str(key, value, iscolor=False)

        elif value_type == list:
            result_info += output_list(key, value, iscolor=False)

        elif value_type == dict:
            result_info += output_dict(key, value, iscolor=False)

        elif value_type == requests.models.Response:
            result_info += output_res(key, value, iscolor=False)

        elif value_type == HackRequests.response:
            result_info += output_Hackres(key, value, iscolor=False)

    return result_info

def output_str(key, value, iscolor=True):
    ''' 接收键值, 返回key: value '''
    info_str = ''

    if iscolor:
        info_str += color.yellow_ex(key) + color.reset(': ' + value + '\n|    ')
    else:
        info_str += key + ': ' + value + '\n|    '
    
    return info_str

def output_list(key, value, iscolor=True):
    ''' 接收键值, 返回key: value1 value2 value3 '''
    info_list = ''

    if iscolor:
        info_list += color.yellow_ex(key) + color.reset(': ')
        for v in value:
            info_list += v + '  '
        info_list += '\n|    '
    else:
        info_list += key + ': '
        for v in value:
            info_list += v + '  '
        info_list += '\n|    '

    return info_list

def output_dict(key, value, iscolor=True):
    ''' 接收键值, 返回 
        key:
            key1: value1
            key2: value2
    '''
    info_dict = ''
    
    if iscolor:
        info_dict += '\r|    ' + color.red_ex(key) + color.reset(':\t' + '\n')
        for k_father, v_father in value.items():
            if ('Headers' == k_father):
                info_dict += '|        ' + color.yellow_ex(k_father + ':\n')
                for k_child, v_child in v_father.items():
                    info_dict += '|            ' + color.yellow_ex(k_child) + color.reset(': ' + v_child + '\n')
            else:
                info_dict += '|        ' + color.yellow_ex(k_father) + color.reset(': ' + v_father + '\n')
    else:
        info_dict += key + ':\t' + '\n'
        for k_father, v_father in value.items():
            if ('Headers' == k_father):
                info_dict += '|        ' + k_father + ':\n'
                for k_child, v_child in v_father.items():
                    info_dict += '|            ' + k_child + ': ' + v_child + '\n'
            else:
                info_dict += '|        ' + k_father + ': ' + v_father + '\n'
    
    return info_dict

def output_res(key, res, iscolor=True):
        ''' 接收一个requests结果, 返回一个http数据包 '''
        info_res = ''

        if iscolor:
            try:
                info_res += color.yellow_ex(key) + ':'
                info_res += color.red_ex(' [Request')
                info_res += color.black_ex('\n' + res.request.method + ' ' + res.request.path_url + ' ' + http.client.HTTPConnection._http_vsn_str)
                info_res += color.black_ex('\n' + 'Host' + ': ' + logger.get_domain(res.request.url))

                for key, value in res.request.headers.items():
                    info_res += color.black_ex('\n' + key + ': ' + value)
                if res.request.body:
                    if (type(res.request.body) == bytes):
                        info_res += color.black_ex('\n\n' + res.request.body.decode())
                    else:
                        info_res += color.black_ex('\n\n' + res.request.body)

                info_res += color.red_ex(']')
                info_res += color.reset('\n    ')
            except:
                return info_res
        else:
            try:
                info_res += key + ':'
                info_res += ' [Request'
                info_res += '\n' + res.request.method + ' ' + res.request.path_url + ' ' + http.client.HTTPConnection._http_vsn_str
                info_res += '\n' + 'Host' + ': ' + logger.get_domain(res.request.url)

                for key, value in res.request.headers.items():
                    info_res += '\n' + key + ': ' + value
                if res.request.body:
                    if (type(res.request.body) == bytes):
                        info_res += '\n\n' + res.request.body.decode()
                    else:
                        info_res += '\n\n' + res.request.body

                info_res += ']\n    '
            except:
                return info_res

        return info_res

def output_Hackres(key, res, iscolor=True):
        ''' 接收一个HackRequests结果, 返回一个http数据包 '''
        info_res = ''

        if iscolor:
            try:
                info_res += color.yellow_ex(key) + ':'
                info_res += color.red_ex(' [Request')
                info_res += color.black_ex('\n' + res.log.get('request'))

                info_res += color.red_ex(']')
                info_res += color.reset('\n    ')
            except:
                return info_res
        else:
            try:
                info_res += key + ':'
                info_res += ' [Request'
                info_res += '\n' + res.log.get('request').replace('\n', '')

                info_res += ']\n    '
            except:
                return info_res

        return info_res