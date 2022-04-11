#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    threading没有返回结果的功能
    重新创建一个threads类, 继承自threading.Thread
    添加返回结果的功能get_result()
'''

from threading import Thread

class thread(Thread):
    def __init__(self, target, url):
        super(thread, self).__init__()
        self.target = target
        self.url = url

    def run(self):
        self.result = self.target(self.url)

    def get_result(self):                   # * 返回子线程扫描结果
        try:
            return self.result              # * 如果子线程不使用join()方法，此处可能会报没有self.result的错误
        except Exception:
            return None