#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# ! 12: from payloads.文件名.main import 对象名称

from lib.initial.config import config
from lib.tool.logger import logger
from lib.tool import check
from lib.tool import timed
from lib.report import output
from lib.tool.thread import thread

from lib.plugins.fingerprint.waf import waf
from lib.plugins.fingerprint.webapp import webapp
from lib.plugins.shell import shell

from PluginManager import PluginManager
from PluginManager import __ALLMODEL__

from thirdparty.tqdm import tqdm
from queue import Queue
from time import sleep
from os import _exit

from lib.core import client

class coreScan():
    def __init__(self):
        self.lang = config.get('lang')                                                              # * 语言
        self.thread = config.get('thread')                                                          # * 线程数
        self.delay = config.get('delay')                                                            # * 延时
        self.url_list = config.get('url_list')                                                      # * url列表
        self.vulns = config.get('vulns')                                                              # * 是否扫描单个漏洞
        self.batch = config.get('batch')                                                            # * 是否启用默认选项
        self.no_waf = config.get('no_waf')                                                          # * 是否启用WAF指纹识别
        self.no_poc = config.get('no_poc')                                                          # * 是否启用WAF指纹识别
        self.shell = config.get('shell')

        self.thread_list = []                                                                       # * 已经运行的线程列表
        self.results = []                                                                           # * 结果列表
        self.queue = Queue()                                                                        # * 创建线程池
        
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')
        self.proxy = config.get('proxy')
        
        self.output_file = config.get('output')                                                     # * 是否导出文件

    def start(self):
        ''' 开始扫描, 添加poc并启动 '''
        self.StartTime = timed.getTime()                                                                # * 记录开始时间/s

        for u in self.url_list:                                                                         # * 遍历urls
            if (('http://' not in u[0:10]) and ('https://' not in u[0:10])):
                logger.info('red_ex', self.lang['core']['start']['url_error'].format(u))
                continue

            if self.shell and (not self.vulns):
                logger.info('yellow_ex', self.lang['core']['start']['shell'])                          # ? 提示, 使用shell之前 请先使用-a和-v参数指定一个漏洞
                break

            logger.info('green_ex', self.lang['core']['start']['start'] + u)                           # ? 提示, 开始扫描当前url

            # todo --------------------创建请求中转客户端--------------------
            self.client = client.RequestsClient(
                base_url=u,
                timeout=self.timeout,
                headers=self.headers,
                proxies=self.proxies
            )
            
            self.hackClient = client.HackRequestsClient(
                base_url=u,
                timeout=self.timeout,
                headers=self.headers,
                proxy=self.proxy
            )
            
            self.clients = {
                'reqClient': self.client,                                                           # * requests
                'hackClient': self.hackClient                                                       # * HackRequests.hackRequests
            }

            if check.check_connect(self.client):
                # * --------------------WAF指纹识别--------------------
                if (not self.no_waf):                                                               # todo 如果没有使用--no-waf选项
                    waf_info = waf.identify(self.client)                                            # * 传递客户端client进行WAF检测

                    if waf_info == 'no':                                                            # * 这个URL有WAF, 不扫了, 换下一个
                        continue

                # * --------------------框架指纹识别--------------------
                self.identify_apps = []
                
                if ((not self.vulns)):
                    webapp.stop = self.stop                                                         # * 添加暂停机制
                    self.identify_apps = webapp.identify(self.client)                               # * 传递客户端client进行框架指纹识别
            else:
                logger.info('red', self.lang['core']['start']['unable'] + u)                        # ? 提示, 无法访问当前url
                continue

            if self.no_poc:                                                                         # todo 是否使用了--no-poc参数
                logger.info('red', self.lang['core']['start']['no_poc'])                            # ? 提示, 不进行漏洞扫描
                continue

            if check.check_connect(self.client):
                self.addPOC()                                                                       # * 为url添加poc 并加入线程池
                self.scanning()                                                                     # * 开始扫描该url
            else:
                logger.info('red', self.lang['core']['start']['unable'] + u)                        # ? 提示, 无法访问当前url
                continue
        self.end()                                                                                  # * 扫描结束, 处理所有poc扫描结果

    def addPOC(self):                                                                               # * 为相应url添加poc
        ''' 为某个url添加相应poc
                如果指纹识别列表有内容, 则扫描识别出的框架
                否则使用默认的框架列表
        '''
        # * 加载Payloads
        logger.info('yellow_ex', self.lang['core']['start']['loadPayload'])
        
        if (self.vulns) and ('all' not in self.vulns):
            PluginManager.LoadAllPlugin(self.vulns)
        else:
            PluginManager.LoadAllPlugin(self.identify_apps)
        
        # * 为每个Payload添加线程
        try:
            for SingleModel in __ALLMODEL__:
                plugins = SingleModel.GetPluginObject()
                for item in plugins:
                    self.queue.put(thread(target=item.Start, clients=self.clients))
        except:
            logger.info('red_ex', self.lang['core']['addpoc']['Error-1'])                           # ? 出错, 添加poc时出现错误
            logger.info('reset', '', notime=True, print_end='')                                     # * 重置文字颜色
            _exit(0)

    def scanning(self):
        ''' 正在扫描, 根据线程数启动poc '''
        queue_thread = int(self.queue.qsize() / self.thread)+1                                      # * 循环次数
        queue_thread = 1 if queue_thread <=0 else queue_thread                                      # * 最小为1
        
        logger.info('yellow_ex', '', notime=True, print_end='')                                         # * 重置文字颜色
        for q in tqdm(range(queue_thread), ncols=50):                                               # * 单个url的扫描进度条
            for i in range(self.thread):                                                        # * 根据线程数, 每次运行相应次数的poc
                try:
                    if not self.queue.empty():                                                      # * 如果线程池不为空, 开始扫描
                        t = self.queue.get()                                                        # * 从线程池取出一个poc
                        t.start()                                                                   # * 运行一个poc
                        self.thread_list.append(t)                                                  # * 往线程列表添加一个已经运行的poc
                    else:                                                                       
                        break                                                                       # * 如果线程池为空, 结束扫描
                    sleep(self.delay)                                                              # * 扫描时间间隔
                except KeyboardInterrupt:
                    if self.stop():
                        continue
                    else:
                        self.queue.queue.clear()                                                        # * 清空当前url的扫描队列
                        break                                                                           # * 停止当前url的扫描, 并扫描下一个url

    def stop(self):
        ''' # ! 功能还没完善
        Ctrl+C暂停扫描
            q(uit)              退出扫描
            c(ontinue)          继续扫描
            n(ext)              跳过当前url的扫描
            m(odify)            (还没写好)修改参数, 输入参数名和值(如-t 3)然后回车, 修改相应参数, 并继续扫描
            wq(save and exit)   等待已经运行的poc, 保存并输出已有的漏洞结果, 有--output参数的话则同步保存至文件
        '''
        while True:
            try:
                logger.info('reset', '', print_end='')                  # ? 提示信息
                operation = input('\r[CTRL+C] - q(uit)/c(ontinue)/n(ext)/wq(save and exit): '.ljust(70))# * 接收参数
                operation = operation.lower()                                                           # * 字母转小写

                if operation in ['q', 'quit']:                                                          # * 退出扫描
                    _exit(0)
                elif operation in ['c', 'continue']:                                                    # * 继续扫描
                    logger.info('yellow_ex', self.lang['core']['stop']['continue'])                     # ? 日志, 继续扫描
                    return True
                elif operation in ['wq', 'save and exit']:                                              # * 保存结果并退出
                    self.end()
                elif operation in ['n', 'next']:
                    logger.info('yellow_ex', self.lang['core']['stop']['next'])                         # ? 日志, 扫描下一个目标

                    return False
            except:
                continue

    def start_shell(self):
        ''' 启动Shell模式 '''

        shell.start(self.results)

    def end(self):
        ''' 结束扫描, 等待所有线程运行完毕, 生成漏洞结果并输出/保存'''
        logger.info('cyan_ex', self.lang['core']['end']['wait'])                                    # ? 日志, 等待所有线程运行完毕, 时间长短取决于timeout参数
        for t in self.thread_list:                                                                  # * 遍历线程列表
            try:
                t.join()                                                                                # * 阻塞未完成的子线程, 等待主线程运行完毕
                self.results.append(t.get_result())                                                     # * 添加扫描结果
            except KeyboardInterrupt:
                continue
        
        output.output_info(self.results, self.lang)                                                 # * output处理扫描结果, 在命令行输出结果信息

        # * 保存扫描结果, .html / .json / .txt
        if (self.output_file == 'html'):
            output.output_html(self.results, self.lang)
        elif (self.output_file == 'json'):
            output.output_json(self.results, self.lang)
        elif (self.output_file == 'txt'):
            output.output_text(self.results, self.lang)

        if self.shell and self.vulns:                                                                # * 是否使用Shell
            self.start_shell()

        self.endTime = timed.getTime()                                                              # * 结束时间
        intervalTime = self.endTime - self.StartTime                                                # * 计算扫描耗时/s

        logger.info('yellow_ex', self.lang['core']['end']['completed'].format(intervalTime))        # ? 日志, 扫描完全结束, 退出运行
        logger.info('reset', '', notime=True, print_end='')                                         # * 重置文字颜色
        print('\r'.ljust(70), end='\r')                                                             # * 解决wq的BUG
        _exit(0)

corescan = coreScan()