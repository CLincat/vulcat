#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    插件:
        POC转EXP
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from lib.tool import head
from thirdparty import requests
from time import sleep
import re

def exp(result):
    pass