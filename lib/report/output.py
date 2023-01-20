#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
from lib.initial.config import config
from lib.tool.timed import nowtime_year, custom_time
from lib.tool.logger import logger
from thirdparty import requests
from thirdparty import HackRequests
import json
import http.client

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
        logger.info('red_ex', lang['output']['info']['vul'].format(logger.requests_number))              # ? 日志, 发现漏洞, 发送的请求包数量为xxx个
        for result in results_info_list:
            print(result, end='')
        logger.info('reset', '---', notime=True)                                                                                    # ? 结果, 重置文字颜色, 输出漏洞结果, 不显示时间
    else:                                                                                                                           # * 没有漏洞
        logger.info('green_ex', lang['output']['info']['notvul'].format(logger.requests_number))                # ? 日志, 目标看起来没有漏洞, 发送的请求包数量为xxx个
    return None

def output_text(results, lang):
    ''' 以txt格式保存扫描结果至文件中
        :param results: POC返回的漏洞信息, 字典类型
        :param lang: 语言
    '''
    try:
        filename = 'vulcat_' + custom_time('%Y-%m-%d_%H-%M-%S') + '.txt'
        results_info_list = []

        for result in results:
            if result:
                f = open(filename, 'a', encoding='utf-8')
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
            logger.info('red_ex', lang['output']['text']['notvul'])                     # ? 日志, 没有漏洞, 未生成文件
            return None
        f.close()
    except:
        logger.info('red_ex', lang['output']['text']['faild'])
    return None

def output_json(results, lang):
    ''' 以json格式保存扫描结果至文件中 
        :param results: POC返回的漏洞信息, 字典类型
        :param lang: 语言
    '''
    try:
        filename = 'vulcat_' + custom_time('%Y-%m-%d_%H-%M-%S') + '.json'
        results_info_list = []

        for result in results:
            if result:
                f = open(filename, 'a', encoding='utf-8')

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
            logger.info('red_ex', lang['output']['json']['notvul'] + filename)         # ? 日志, 没有漏洞, 未生成文件
            return None
        f.close()
    except:
        logger.info('red_ex', lang['output']['json']['faild'])
    return None

def output_html(results, lang):
    ''' 以html格式保存扫描结果至文件中
    
    '''
    
    try:
        filename = 'vulcat_' + custom_time('%Y-%m-%d_%H-%M-%S') + '.html'
        vulnContents = []
        idNum = 0
        
        for i in range(len(results)):
            result = results[i]
            if (not result):
                continue
            
            idNum += 1
            
            vulnContent = {
                'id': idNum,
                'fullUrl': result['Target'],
                'target': logger.get_domain(result['Target'], protocol=True),
                'ftype': result['Type'][0] + '/' + result['Type'][1],
                'vulnid': result['Type'][2],
                'time': nowtime_year(),
                'requests': []
            }
            
            for resKey, resValue in result.items():
                if ('request' in resKey.lower()):
                    # * requests/HackRequests请求的返回值 -> 解析为 HTTP数据包字符串
                    if type(resValue) == requests.models.Response:
                        requestStr = output_res('', resValue, iscolor=False)
                    elif type(resValue) == HackRequests.response:
                        requestStr = output_Hackres('', resValue, iscolor=False)

                    startIndex = requestStr.find('[Request\n') + len('[Request\n')
                    endIndex = requestStr.rfind(']')
                    requestStr = requestStr[startIndex:endIndex]

                    resValueHtmlEncode = html_encode(requestStr)        # * 对 HTTP数据包字符串 进行HTML实体编码
                    vulnContent['requests'].append(resValueHtmlEncode)
            
            vulnContents.append(vulnContent)
        
        
        if vulnContents:  
            vulns = 'var vulnContent=' + str(vulnContents) + ';'
            
            f = open(filename, 'a', encoding='utf-8')
            f.write(htmlStart + vulns + jsStart + jstEnd + htmlEnd)
            f.close()
            
            logger.info('cyan_ex', lang['output']['html']['success'] + filename)        # ? 日志, 已保存结果至XXX.txt文件中
        else:
            logger.info('red_ex', lang['output']['html']['notvul'])                     # ? 日志, 没有漏洞, 未生成文件
            return None
        f.close()
    except:
        logger.info('red_ex', lang['output']['html']['faild'])
    return None

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

def output_vul_info(result, old_str='\n'):
    ''' 漏洞信息, 无颜色, 用于保存结果至文件中
            :param result: vulcat的单个poc扫描结果
            :param old_str: 适配Exploit模式, 其它情况下不用理会
    '''
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
            result_info += output_Hackres(key, value, iscolor=False, old_str=old_str)

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

def output_Hackres(key, res, iscolor=True, old_str='\n'):
        ''' 接收一个HackRequests结果, 返回一个http数据包
                :param key: 字典key值
                :param res: HackRequests.Response
                :param iscolor: 颜色
                :param old_str: 用来适配Exploit模式, exp不能使用带换行的
                :return: 带颜色/无颜色的http请求数据包
        '''
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
                info_res += '\n' + res.log.get('request').replace(old_str, '')

                info_res += ']\n    '
            except:
                return info_res

        return info_res

def html_encode(oldStr: str):
    ''' 对字符串进行HTML实体编码
            :param oldStr: 需要编码的字符串
            :return newStr: 编码后的字符串
    '''
    
    # * 需要编码的字符, 长度33
    # htmlLabel = [" ", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?", "@", "[", "\\", "]", "^", "_", "`", "{", "|", "}", "~"]
    htmlLabel = ["&", "<", ">", "\"", "'"]
    
    # * 编码后的字符, 长度33, 与上面一一对应
    # htmlLabelEncode = ["&nbsp;", "&excl;", "&quot;", "&num;", "&dollar;", "&percnt;", "&amp;", "&apos;", "&lpar;", "&rpar;", "&ast;", "&plus;", "&comma;", "&hyphen;", "&period;", "&sol;", "&colon;", "&semi;", "&lt;", "&equals;", "&gt;", "&quest;", "&commat;", "&lsqb;", "&bsol;", "&rsqb;", "&circ;", "&lowbar;", "&grave;", "&lcub;", "&verbar;", "&rcub;", "&tilde;"]
    htmlLabelEncode = ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"]
    
    newStr = oldStr
    for i in range(len(htmlLabel)):
        newStr = newStr.replace(htmlLabel[i], htmlLabelEncode[i])      

    return newStr

# * .html报告 起始和结束 部分
htmlStart = r'''<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Document</title><style>* {margin: 0;padding: 0;}html {position: relative;}ul, ol, li {list-style: none;height: 40px;}a {text-decoration: none;color: rgb(0, 102, 255);}a:hover {color: rgba(0, 102, 255, 0.8);}li {float: left;text-align: center;line-height: 40px;}html {width: 100%;height: auto;}body {height: 100%;}header {width: 100%;height: 71px;background-color: #00bc8c;}header .top {position: relative;float: right;width: 87%;}header .top ul {position: absolute;top: 20px;right: 100px;width: 60px;text-align: center;height: 35px;line-height: 35px;background-color: red;}header .top ul:hover li {display: block;}header .top ul li:hover {cursor: pointer;}header .top ul li {display: none;width: 100px;border-bottom: 1px solid black;background-color: rgb(0, 255, 170);}header .logo {float: left;width: 13%;height: 100%;Letter-spacing: 1px;font-size: 10px;}header .logo a {color: white;}.right .nav .icon {margin-left: 35px;margin-top: 12px;height: 0;overflow: hidden;}.right .main {border: 1px solid rgb(155, 157, 161);}.right .main .icon {margin-left: 20px;width: 15px;height: 15px;border: 1px solid black;margin-top: 12px;line-height: 15px;}.right .main .icon:hover {cursor: pointer;}.right {float: left;width: 80%;height: 100%;}.right nav {width: 100%;height: 40px;}.right nav ul {background-color: rgba(229, 231, 235, 0.5);}.left ul:hover,.left ul li:hover,.right .main ul:hover,.right nav ul li:hover {background-color: rgba(0, 225, 255, 0.5);}.right nav ul li:not(:first-child) {cursor: pointer;}.right .main ul {clear: both;border: 1px solid rgba(229, 231, 235, 0.6);}.right .main ul li {height: auto;}.right .main .requests {width: 99%;height: 600px;overflow-y: scroll;margin: 0px 0px 20px 5px;display: none;}.right .main .requests table {width: 100%;}.right .main .requests table tbody tr td {text-align: left;height: auto;border: 1px solid rgb(193, 197, 197);padding-left: 5px;}.right .main .requests table tbody tr:nth-child(odd):not(:first-child) {background-color: rgba(255, 250, 232, 0.3);}.right .main .requests table tbody tr:nth-child(even) {background-color: rgba(229, 231, 235, 0.5);}.right .main .requests table tbody tr td span {margin-left: 20px;color: blue;}.right .main .requests table tbody tr td span:hover {cursor: pointer;color: skyblue;}.right .main table tbody tr td code {white-space: pre-line;}#copy_success {background-color: rgb(253, 255, 254);box-shadow: 0 0 5px 0 black;text-align: center;line-height: 40px;position: absolute;z-index: 10;width: 100px;height: 40px;left: 50%;top: 50%;margin-left: -100px;margin-top: -40px;color: rgb(56, 226, 56);}footer {position: absolute;bottom: -100px;width: 100%;height: 30px;font-size: 14px;line-height: 30px;text-align: center;padding-bottom: 30px;}.left {float: left;width: 20%;height: 550px;overflow-y: scroll;scrollbar-color: #00bc8c;}.left>ul {position: relative;text-align: center;line-height: 40px;width: 100%;border-bottom: 1px solid rgb(155, 157, 161);clear: both;}.left>ul:not(:first-child) {border-top: 1px solid rgb(155, 157, 161);}.left>ul>input {position: absolute;left: 10px;top: 15px;width: 15px;height: 15px;}.left>ul>input:hover {cursor: pointer;}.left>ul .arrow {display: inline-block;width: 0;height: 0;border: 8px solid;border-color: transparent transparent black transparent;}.left>ul i {position: absolute;width: 35px;}.left>ul i:hover {cursor: pointer;}.left>ul>strong {display: inline-block;width: 75%;border-right: 1px solid red;}.left>ul li {position: relative;display: none;width: 100%;}.left>ul li input {position: absolute;left: 30px;top: 15px;width: 15px;height: 15px;}.left>ul li input:hover {cursor: pointer;}.left>ul li span {display: inline-block;margin-left: 40px;height: 100%;width: 86%;}</style></head><body><!-- 头部 --><header><div class="logo"></div><div class="top"></div></header><!-- 侧边栏 --><div class="left"></div><!-- 内容展示区 --><div class="right"><nav class="nav"></nav><main class="main"></main></div><!-- 底部 --><footer><a href="https://github.com/CLincat/vulcat" target="_blank">https://github.com/CLincat/vulcat</a></footer><script>'''
jsStart = r'''var __spreadArrays=(this&&this.__spreadArrays)||function(){for(var s=0,i=0,il=arguments.length;i<il;i++)s+=arguments[i].length;for(var r=Array(s),k=0,i=0;i<il;i++)for(var a=arguments[i],j=0,jl=a.length;j<jl;j++,k++)r[k]=a[j];return r};var vulnTitle=[{"id":"ID","target":"Target","ftype":"Framework/Type","vulnid":"VulnID","time":"Time"}];function add_click_each(eLements,tEvent){eLements.forEach(function(item,index){item.addEventListener("click",tEvent)})}var initHtmlStyle=document.querySelector("style").innerHTML;var HtmlStyle={"default":{},"cerculean":{"backgroundColor":"#ffffff","a":"#4bb1ea","ul_li_hover":"#a9b3be","ul_li_hover_fontColor":"white","header":"#84b251","a_hover":"#225384","border":"#a1b5ca","fontColor":"#2fa4e7","style_ul":"#cf3c40","style_ul_li":"#e16e25","nav":"#a3d7f4","main_ul":"#ffffff"},"morph":{"backgroundColor":"#d9e3f1","a":"#378dfc","ul_li_hover":"#aaaaaa","ul_li_hover_fontColor":"white","header":"#43cc29","a_hover":"#5a61f4","border":"#8189f1","fontColor":"#7e8db9","style_ul":"#e52527","style_ul_li":"#ffc107","nav":"#003f92","main_ul":"#f0f5fa"},"darkly":{"backgroundColor":"#222222","a":"#375a7f","ul_li_hover":"#444444","ul_li_hover_fontColor":"#ffffff","header":"#00bc8c","a_hover":"#3498db","border":"#2d72a1","fontColor":"#ffffff","style_ul":"#e74c3c","style_ul_li":"#f39c12","nav":"#375a7f","main_ul":"#2f2f2f"},"superhero":{"backgroundColor":"#2b3e50","a":"#4c9be8","ul_li_hover":"#4e5d6c","ul_li_hover_fontColor":"#ffffff","header":"#5cb85c","a_hover":"#5bc0de","border":"#4b97b2","fontColor":"#ffffff","style_ul":"#d9534f","style_ul_li":"#f0ad4e","nav":"#4c9be8","main_ul":"#32465a"}};var classTop=document.querySelector(".top");var classTopHtml="<ul>Style";for(var _i=0,_a=Object.entries(HtmlStyle);_i<_a.length;_i++){var _b=_a[_i],key=_b[0],val=_b[1];classTopHtml+="<li>"+key+"</li>"}classTopHtml+="</ul>";classTop.innerHTML=classTopHtml;function select_style(event){var styleName=event.target.textContent;var labelStyle=document.querySelector("style");var style=HtmlStyle[styleName];labelStyle.innerHTML=initHtmlStyle;if(styleName=="default"){return}labelStyle.innerHTML+="html {\n\t\tbackground-color: "+style["backgroundColor"]+";}\n";labelStyle.innerHTML+="a,\n\t.right .main .requests table tbody tr td span {\n\t\tcolor: "+style["a"]+";}\n";labelStyle.innerHTML+=".left ul:hover,\n\t.left ul li:hover,\n\t.right .main ul:hover,\n\t.right nav ul li:hover {\n\t\tbackground-color: "+style["ul_li_hover"]+";}\n";labelStyle.innerHTML+=".left ul:hover strong,\n\t.left ul li:hover,\n\t.right .main ul:hover li:not(:last-child),\n\t.right nav ul li:hover {\n\t\tcolor: "+style["ul_li_hover_fontColor"]+";}\n";labelStyle.innerHTML+="header {\n\t\tbackground-color: "+style["header"]+";}\n";labelStyle.innerHTML+="a:hover,\n\t.right .main .requests table tbody tr td span:hover {\n\t\tcolor: "+style["a_hover"]+";}\n";labelStyle.innerHTML+="header .top ul li,\n\t.right .main,\n\t.right .main .icon,\n\t.right .main ul,\n\t.right .main .requests table tbody tr td,\n\t.left>ul,\n\t.left>ul:not(:first-child),\n\t.left>ul>strong {\n\t\tborder-color: "+style["border"]+";}\n";labelStyle.innerHTML+=".left, .right {\n\t\tcolor: "+style["fontColor"]+";}\n";labelStyle.innerHTML+="header .top ul {\n\t\tbackground-color: "+style["style_ul"]+";}\n";labelStyle.innerHTML+="header .top ul li {\n\t\tbackground-color: "+style["style_ul_li"]+";}\n";labelStyle.innerHTML+=".right nav ul {\n\t\tbackground-color: "+style["nav"]+";}\n";labelStyle.innerHTML+=".right main ul {\n\t\tbackground-color: "+style["main_ul"]+";}\n"}var classTopUlLi=document.querySelectorAll(".top ul li");add_click_each(classTopUlLi,select_style);var a="\n                  ___                   _____\n  _    _  _   _   | |     ____   ____  [_____]\n | \\  / /| | | |  | |    / ___) / _  ]   | |\n  \\ \\/ / | (_/ |  | |__ ( (___ ( [_] |   | |\n   \\__/  (____ ]/[_____] \\____) \\____]/  [_]\n";var logo=document.querySelector(".logo");logo.innerHTML="<a href=\"\"><pre>"+a+"</pre></a>";var bool=true;var noShowList=[];var noShowTrList={"target":[],"vulnid":[],"ftype":[],"time":[]};function sort(arr,dataLeven,bool){function getValue(option){if(!dataLeven)return option;var data=option;dataLeven.split('.').filter(function(item){data=data[item]});return data+''}arr.sort(function(item1,item2){if(bool){return getValue(item1).localeCompare(getValue(item2))}return getValue(item2).localeCompare(getValue(item1))})}function show_sort(event){var className=event.target.className;bool=!bool;sort(vulnContent,className,bool);show()}var classNav=document.querySelector(".nav");var classMain=document.querySelector(".main");function show(noShow,noShowTr){if(noShow===void 0){noShow=noShowList}if(noShowTr===void 0){noShowTr=noShowTrList}var len=Object.keys(vulnTitle[0]).length;var width="width:"+(96/len)+"%;";var classNavHtml="<ul>";var classMainHtml="";vulnTitle.forEach(function(item,index){classNavHtml+="<li class=\"icon\"></li>";for(var _i=0,_a=Object.entries(item);_i<_a.length;_i++){var _b=_a[_i],key=_b[0],val=_b[1];if(noShow.includes(key)){continue}classNavHtml+="<li class=\""+key+"\">"+val+"</li>"}classNavHtml+="</ul>"});vulnContent.forEach(function(content_item,content_index){var i=-1;var _loop_1=function(key,val){val.forEach(function(val_item,val_index){if(!(i+1)){i=content_item[key].indexOf(val_item)}})};for(var _i=0,_a=Object.entries(noShowTr);_i<_a.length;_i++){var _b=_a[_i],key=_b[0],val=_b[1];_loop_1(key,val)}if(i+1){}else{classMainHtml+="<ul>";var fullUrl='';for(var _c=0,_d=Object.entries(content_item);_c<_d.length;_c++){var _e=_d[_c],key=_e[0],val=_e[1];if(noShow.includes(key)){continue}if(key=="id"){classMainHtml+="<li class=\"icon\">+</li>";classMainHtml+="<li class=\""+key+"\">";classMainHtml+=val;classMainHtml+="</li>"}else if(key=="fullUrl"){fullUrl=val}else if(key=="requests"){classMainHtml+="<li class=\""+key+"\">";classMainHtml+="<table>";classMainHtml+="<tbody>";classMainHtml+="<tr><td><a href=\""+fullUrl+"\" target=_blank>"+fullUrl+"</a></td></tr>";val.forEach(function(reqValItem,reqValIndex){classMainHtml+="<tr><td><strong>Request-"+(reqValIndex+1)+"</strong><span>Copy</span></td></tr>";classMainHtml+="<tr><td><code>"+reqValItem+"</code></td></tr>"});classMainHtml+="</tbody>";classMainHtml+="</table>";classMainHtml+="</li>"}else{classMainHtml+="<li class=\""+key+"\">"+val+"</li>"}}classMainHtml+="</ul>"}});'''

jstEnd = r'''classNav.innerHTML=classNavHtml;classMain.innerHTML=classMainHtml;var classNavLis=document.querySelectorAll(".nav ul li:not(:first-child)");var classMainLis=document.querySelectorAll(".main ul li:not(:last-child):not(:first-child)");var lis=__spreadArrays(classNavLis,classMainLis);lis.forEach(function(item,index){item.setAttribute("style",width)});var classNavLis_2=document.querySelectorAll(".nav ul li");add_click_each(classNavLis_2,show_sort);var classMainLis_2=document.querySelectorAll(".main ul li:not(:last-child)");hide_each(classMainLis);var requestsCopys=document.querySelectorAll(".right .main .requests table tbody tr td span");add_click_each(requestsCopys,requests_copy)}function requests_copy(event){var content_txt=event.target.parentNode.parentNode.nextSibling.textContent;var selBox=document.createElement('textarea');selBox.value=content_txt;document.body.appendChild(selBox);selBox.select();document.execCommand('copy');document.body.removeChild(selBox);var copy_success=document.createElement("div");copy_success.id="copy_success";if(document.getElementById("copy_success")==null){document.body.appendChild(copy_success);copy_success.innerHTML="<strong>Copy Success!!!</strong>";setTimeout("document.body.removeChild(copy_success)",2000)}}sort(vulnContent,'id',bool);show();function show_or_hide_requests(event,show){if(show===void 0){show=true}var parent=event.target.parentNode;var requests_li=parent.lastChild;var icon_span=parent.firstChild;var main_li=parent.childNodes;if(show){requests_li.setAttribute("style","display:block;");icon_span.innerText="-";show_each(main_li)}else{requests_li.setAttribute("style","display:none;");icon_span.innerText="+";hide_each(main_li)}var req_li=document.querySelectorAll(".requests");req_li.forEach(function(item,index){item.removeEventListener("click",show_requests);item.removeEventListener("click",hide_requests)})}function show_each(main){main.forEach(function(item,index){item.removeEventListener("click",show_requests)});add_click_each(main,hide_requests)}function hide_each(main){main.forEach(function(item,index){item.removeEventListener("click",hide_requests)});add_click_each(main,show_requests)}function show_requests(event){show_or_hide_requests(event)}function hide_requests(event){show_or_hide_requests(event,false)}function filter_show(className){var noShowTr=className.split("_");var noShows=noShowTrList[noShowTr[0]];var no=noShowTr[1];if(noShows.includes(no)){var i=noShows.indexOf(no);if(i+1){noShows.splice(i,1)}}else{noShows.push(no)}show()}function create_filter(vulnArr,noCreate){var filter=[];vulnArr.forEach(function(item,index){filter[index]={};for(var _i=0,_a=Object.entries(item);_i<_a.length;_i++){var _b=_a[_i],key=_b[0],val=_b[1];if(!noCreate.includes(key)){filter[index][key]=val;if(key=="ftype"){var f_type=val.split("/");filter[index]["framework"]=f_type[0];filter[index]["type"]=f_type[1]}}}});return filter}var vulnTitleFilter=create_filter(vulnTitle,["id"]);var vulnContentFilter=create_filter(vulnContent,["id","requests"]);var leftHtml="";vulnTitleFilter.forEach(function(item,index){var itemKeyList=[];var _loop_2=function(key,val){leftHtml+="<ul class=\""+key+"\">";if(!["framework","type"].includes(key)){leftHtml+="<input type=checkbox class=\""+key+"\" checked>";}leftHtml+="<strong>"+val+"</strong><i><span class=\"arrow "+key+"\"></span></i>";leftHtml+="<li class=\"all left_"+key+"\">";leftHtml+="<input type=\"checkbox\" class=\"all_"+key+"\" checked>";leftHtml+="<span>All</span></li>";vulnContentFilter.forEach(function(item,index){var itemKeyValue;if(key=="time"){itemKeyValue=item[key].split(" ")[0]}else{itemKeyValue=item[key]}if(!(itemKeyList.includes(itemKeyValue))){leftHtml+="<li class=left_"+key+">";if(["framework","type"].includes(key)){var noShowKey="ftype"}else{var noShowKey=key}leftHtml+="<input type=\"checkbox\" class=\""+noShowKey+"_"+itemKeyValue+"\" checked>";leftHtml+="<span>"+itemKeyValue+"</span></li>";itemKeyList.push(itemKeyValue)}});leftHtml+="</ul>"};for(var _i=0,_a=Object.entries(item);_i<_a.length;_i++){var _b=_a[_i],key=_b[0],val=_b[1];_loop_2(key,val)}});var left=document.querySelector(".left");left.innerHTML=leftHtml;var classLeftUlLi_1=document.querySelectorAll(".left>ul :nth-child(1)");var classLeftUlLi_2=document.querySelectorAll(".left>ul :nth-child(2)");add_click_each(classLeftUlLi_1,filter_current_title);add_click_each(classLeftUlLi_2,filter_current_title);function filter_current_title(event){var parent=event.target.parentNode;var checkbox=parent.firstChild;if(event.target.nodeName!="INPUT"){checkbox.checked=!checkbox.checked}if(checkbox.checked){var i=noShowList.indexOf(checkbox.className);if(i+1){noShowList.splice(i,1)}}else{noShowList.push(checkbox.className)}show()}function filter_current_main(event){if(event.target.nodeName=="INPUT"){var target=event.target}else{var target=event.target.previousSibling}filter_show(target.className)}var classLeftUlLis_1=document.querySelectorAll(".left>ul li:not(.all)>input");var classLeftUlLis_2=document.querySelectorAll(".left>ul li:not(.all)>span");add_click_each(classLeftUlLis_1,filter_current_main);add_click_each(classLeftUlLis_2,filter_current_main);function select_current_all_li(event){var parent=event.target.parentNode;var allInput=parent.firstChild;var className=parent.className.replace("all ",".");var current_lis=document.querySelectorAll(className+":not(.all)");current_lis.forEach(function(item,index){var itemInput=item.firstChild;if(allInput.checked!=itemInput.checked){filter_show(itemInput.className);itemInput.checked=!itemInput.checked}})}var classleftAll_1=document.querySelectorAll(".left ul .all>input");var classleftAll_2=document.querySelectorAll(".left ul .all>span");add_click_each(classleftAll_1,select_current_all_li);add_click_each(classleftAll_2,select_current_all_li);function show_current_li(event){if(event.target.nodeName=="SPAN"){var target=event.target}else{var target=event.target.firstChild}var className=target.className.replace("arrow ",".left_");var current_lis=document.querySelectorAll(className);current_lis.forEach(function(item,index){if(item.style.display=="block"){item.style.display="none";target.style.borderColor="transparent transparent black transparent"}else{item.style.display="block";target.style.borderColor="black transparent transparent transparent"}})}var leftArrow=document.querySelectorAll(".left>ul>i");add_click_each(leftArrow,show_current_li);'''
htmlEnd = r'''</script></body></html>'''
