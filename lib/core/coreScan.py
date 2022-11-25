#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# ! 12: from payloads.文件名.main import 对象名称

from lib.initial.config import config
from lib.tool.logger import logger
from lib.tool import check
from lib.report import output

from lib.plugins.fingerprint.waf import waf
from lib.plugins.fingerprint.webapp import webapp
from lib.plugins.exploit import exploit

from payloads.AlibabaDruid.main import alidruid
from payloads.AlibabaNacos.main import nacos
from payloads.ApacheAirflow.main import airflow
from payloads.ApacheAPISIX.main import apisix
from payloads.ApacheFlink.main import flink
from payloads.ApacheHadoop.main import hadoop
from payloads.ApacheHttpd.main import httpd
from payloads.ApacheSkyWalking.main import skywalking
from payloads.ApacheSolr.main import solr
from payloads.ApacheTomcat.main import tomcat
# from payloads.ApacheStruts2 import struts2        # 2022/11/04被移除
from payloads.AppWeb.main import appweb
from payloads.AtlassianConfluence.main import confluence
from payloads.Cisco.main import cisco
from payloads.Discuz.main import discuz
from payloads.Django.main import django
from payloads.Drupal.main import drupal
from payloads.ElasticSearch.main import elasticsearch
from payloads.F5BIGIP.main import f5bigip
from payloads.Fastjson.main import fastjson
from payloads.Gitea.main import gitea
from payloads.Gitlab.main import gitlab
from payloads.Grafana.main import grafana
from payloads.Influxdb.main import influxdb
from payloads.Jenkins.main import jenkins
from payloads.Jetty.main import jetty
from payloads.Jupyter.main import jupyter
from payloads.Keycloak.main import keycloak
# from payloads.Kindeditor.main import kindeditor        # 还未测试poc准确性
from payloads.Landray.main import landray
from payloads.MiniHttpd.main import minihttpd
from payloads.MongoExpress.main import mongoexpress
from payloads.Nexus.main import nexus
from payloads.Nodejs.main import nodejs
from payloads.NodeRED.main import nodered
from payloads.phpMyadmin.main import phpmyadmin
from payloads.phpUint.main import phpunit
from payloads.RubyOnRails.main import rails
from payloads.ShowDoc.main import showdoc
from payloads.Spring.main import spring
from payloads.Supervisor.main import supervisor
from payloads.ThinkPHP.main import thinkphp
from payloads.Ueditor.main import ueditor
from payloads.uWSGIPHP.main import uwsgiphp
from payloads.Weblogic.main import weblogic
from payloads.Webmin.main import webmin
from payloads.Yonyou.main import yonyou
from payloads.Zabbix.main import zabbix

from thirdparty.tqdm import tqdm
from queue import Queue
from time import sleep
from os import _exit

class coreScan():
    def __init__(self):
        self.lang = config.get('lang')                                                              # * 语言
        self.thread = config.get('thread')                                                          # * 线程数
        self.delay = config.get('delay')                                                            # * 延时
        self.url_list = config.get('url_list')                                                      # * url列表
        self.app_list = config.get('app_list')                                                      # * 框架列表
        self.application = config.get('application')
        self.vuln = config.get('vuln')                                                              # * 是否扫描单个漏洞
        self.batch = config.get('batch')                                                            # * 是否启用默认选项
        self.no_waf = config.get('no_waf')                                                          # * 是否启用WAF指纹识别
        self.no_poc = config.get('no_poc')                                                          # * 是否启用WAF指纹识别
        self.exp = config.get('exp')

        self.thread_list = []                                                                       # * 已经运行的线程列表
        self.results = []                                                                           # * 结果列表
        self.queue = Queue()                                                                        # * 创建线程池
        self.txt_filename = config.get('txt_filename')
        self.json_filename = config.get('json_filename')
        # self.html_filename = config.get('html_filename')

    def start(self):
        ''' 开始扫描, 添加poc并启动 '''
        for u in self.url_list:                                                                         # * 遍历urls
            if (('http://' not in u[0:10]) and ('https://' not in u[0:10])):
                logger.info('red_ex', self.lang['core']['start']['url_error'].format(u))
                continue

            if self.exp and (not self.vuln):
                logger.info('yellow_ex', self.lang['core']['start']['exp'])                            # ? 提示, 使用exp之前 请先使用-a和-v参数指定一个漏洞
                break

            logger.info('green_ex', self.lang['core']['start']['start'] + u)                           # ? 提示, 开始扫描当前url

            if check.check_connect(u):
                # * --------------------WAF指纹识别--------------------
                if (not self.no_waf):
                    waf_info = waf.identify(u)                                                     # * WAF指纹识别
                    if waf_info:
                        while True:
                            if (not self.batch):                                                            # * 是否使用默认选项
                                logger.info('red', '', print_end='')
                                operation = input(self.lang['core']['waf_finger']['waf_find'].format(waf_info))       # * 接收参数
                            else:
                                logger.info('red', self.lang['core']['waf_finger']['waf_find'].format(waf_info), print_end='')
                                operation = 'no'                                                            # * 默认选项No
                                logger.info('red', 'no', notime=True)

                            operation = operation.lower()                                                   # * 字母转小写
                            if operation in ['y', 'yes']:                                                   # * 继续扫描
                                logger.info('yellow_ex', self.lang['core']['stop']['continue'])             # ? 日志, 继续扫描
                                break
                            elif operation in ['n', 'no']:
                                logger.info('yellow_ex', self.lang['core']['stop']['next'])                 # ? 日志, 下一个
                                u = 'next'
                                break
                    else:
                        logger.info('yellow_ex', self.lang['core']['waf_finger']['waf_not_find'])

                if u == 'next':
                    continue
                # * --------------------WAF指纹识别--------------------

                # * --------------------框架指纹识别--------------------
                if ((self.application == 'auto') and (not self.vuln)):
                    logger.info('yellow_ex', self.lang['core']['web_finger']['web'])
                    webapp.stop = self.stop
                    new_app_list = webapp.identify(u)
                    if new_app_list:
                        logger.info('yellow_ex', self.lang['core']['web_finger']['web_find'].format(str(new_app_list)))
                        self.app_list = new_app_list
                    else:
                        logger.info('yellow_ex', self.lang['core']['web_finger']['web_not_find'])

                # * --------------------框架指纹识别--------------------
            else:
                logger.info('red', self.lang['core']['start']['unable'] + u)                        # ? 提示, 无法访问当前url
                continue

            if self.no_poc:
                logger.info('red', self.lang['core']['start']['no_poc'])                            # ? 提示, 不进行漏洞扫描
                continue

            if check.check_connect(u):
                self.addPOC(u)                                                                      # * 为url添加poc 并加入线程池
                self.scanning()                                                                     # * 开始扫描该url
            else:
                logger.info('red', self.lang['core']['start']['unable'] + u)                        # ? 提示, 无法访问当前url
                continue
        self.end()                                                                                  # * 扫描结束, 处理所有poc扫描结果

    def addPOC(self, url):                                                                          # * 为相应url添加poc
        ''' 为某个url添加相应poc '''
        # * -v/--vuln 参数, 扫描单个漏洞
        try:
            if self.vuln:
                if len(self.app_list) == 1:
                    app = self.app_list[0].lower()
                    poc = eval('{}.addscan("{}", "{}")'.format(app, url, self.vuln))
                    self.queue.put(poc)
                    return
                else:
                    logger.info('red_ex', self.lang['core']['addpoc']['vuln_error_1'])
                    logger.info('reset', '', notime=True, print_end='')                             # * 重置文字颜色
                    _exit(0)
        except:
            logger.info('red_ex', self.lang['core']['addpoc']['vuln_error_2'])                      # ? 出错, 添加poc时出现错误
            logger.info('reset', '', notime=True, print_end='')                                     # * 重置文字颜色
            _exit(0)

        # * 扫描多个漏洞
        try:
            for app in self.app_list:                                                               # * 根据框架列表app_list, 获取相应poc
                app = app.lower()                                                                   # * 转小写
                pocs = eval('{}.addscan("{}")'.format(app, url))
                for poc in pocs:                                                                    # * 将每个poc加入线程池
                    self.queue.put(poc)
        except NameError:
            logger.info('red_ex', self.lang['core']['addpoc']['notfound'] + app)                    # ? 出错, 未找到该框架
            logger.info('reset', '', notime=True, print_end='')                                     # * 重置文字颜色
            _exit(0)
        except:
            logger.info('red_ex', self.lang['core']['addpoc']['error'])                             # ? 出错, 添加poc时出现错误
            logger.info('reset', '', notime=True, print_end='')                                     # * 重置文字颜色
            _exit(0)


    def scanning(self):
        ''' 正在扫描, 根据线程数启动poc '''
        queue_thread = int(self.queue.qsize() / self.thread)+1                                      # * 循环次数
        queue_thread = 1 if queue_thread <=0 else queue_thread                                      # * 最小为1

        for q in tqdm(range(queue_thread), ncols=50):                                               # * 单个url的扫描进度条
            try:
                for i in range(self.thread):                                                        # * 根据线程数, 每次运行相应次数的poc
                    if not self.queue.empty():                                                      # * 如果线程池不为空, 开始扫描
                        t = self.queue.get()                                                        # * 从线程池取出一个poc
                        t.start()                                                                   # * 运行一个poc
                        self.thread_list.append(t)                                                  # * 往线程列表添加一个已经运行的poc
                    else:                                                                       
                        break                                                                       # * 如果线程池为空, 结束扫描
                sleep(self.delay)                                                                   # * 扫描时间间隔
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

    def start_exp(self):
        ''' 启动Exploit模式 '''
        try:
            f = open('Exploit.lock')
            f.close()
            logger.info('red', self.lang['core']['start_exp']['lock'])                             # ? 日志, 使用exp时 请先删除vulcat/Exploit.lock锁文件
        except FileNotFoundError:
            exploit.start(self.results)

    def end(self):
        ''' 结束扫描, 等待所有线程运行完毕, 生成漏洞结果并输出/保存'''
        logger.info('cyan_ex', self.lang['core']['end']['wait'])                                    # ? 日志, 等待所有线程运行完毕, 时间长短取决于timeout参数
        for t in self.thread_list:                                                                  # * 遍历线程列表
            t.join()                                                                                # * 阻塞未完成的子线程, 等待主线程运行完毕
            self.results.append(t.get_result())                                                     # * 添加扫描结果
        output.output_info(self.results, self.lang)                                                 # * output处理扫描结果, 在命令行输出结果信息

        if self.txt_filename:                                                                       # * 是否保存结果为.txt
            output.output_text(self.results, self.txt_filename, self.lang)
        if self.json_filename:                                                                      # * 是否保存结果为.json
            output.output_json(self.results, self.json_filename, self.lang)
        # if self.html_filename:
        #     output.output_html(self.results, self.html_filename, self.lang)

        if self.exp and self.vuln:                                                                  # * 是否使用Exp
            self.start_exp()

        logger.info('yellow_ex', self.lang['core']['end']['completed'])                             # ? 日志, 扫描完全结束, 退出运行
        logger.info('reset', '', notime=True, print_end='')                                         # * 重置文字颜色
        print('\r'.ljust(70), end='\r')                                                             # * 解决wq的BUG
        _exit(0)

corescan = coreScan()