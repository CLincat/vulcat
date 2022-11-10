#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.initial.banner import banner
from lib.initial.parse import parse
from lib.initial.list import list
from lib.initial.config import config_init
from lib.tool import color
import os

banner()                                        # * 横幅

try:
    args = parse()[0]                           # * 参数接收
    list() if args.list else None               # * 是否显示漏洞列表        
    if args.url or args.file:
        config_init(args)                       # * 配置初始化, 加载全局变量
        from lib.core.coreScan import corescan  # * 导入核心扫描模块
        corescan.start()                        # * 开始扫描
    else:
        print('''Please specify parameters, example:
    python3 vulcat.py -h
    python3 vulcat.py -u http://www.example.com/
    python3 vulcat.py -f url.txt
    python3 vulcat.py --list
    python3 vulcat.py --version
''')
except KeyboardInterrupt:
    print(color.reset('CTRL + C exit the scan'))
    os._exit(0)
# except Exception as e:
#     print(e)