#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from thirdparty.colorama import init, Fore, Back, Style

init()                                 # * 初始化, 使Windows机器也能正常显示颜色

def reset(s):
    return Fore.RESET + s

def red(s):                            # * 红色
    return Fore.RED + s

def green(s):                          # * 绿色
    return Fore.GREEN + s

def cyan(s):                           # * 青蓝
    return Fore.CYAN + s

def black_ex(s):                       # * 黑色(高亮)
    return Fore.LIGHTBLACK_EX + s

def red_ex(s):                         # * 红色(高亮)
    return Fore.LIGHTRED_EX + s

def green_ex(s):                       # * 绿色(高亮)
    return Fore.LIGHTGREEN_EX + s

def yellow_ex(s):                      # * 黄色(高亮)
    return Fore.LIGHTYELLOW_EX + s

def blue_ex(s):                        # * 蓝色(高亮)
    return Fore.LIGHTBLUE_EX + s

def magenta_ex(s):                     # * 紫色(高亮)
    return Fore.LIGHTMAGENTA_EX + s

def cyan_ex(s):                        # * 青蓝(高亮)
    return Fore.LIGHTCYAN_EX + s






# from colorama import init
# from colorama import Fore, Back, Style
# from termcolor import colored

# # use Colorama to make Termcolor work on Windows too
# init()
# print(Fore.MAGENTA + 'some red text')
# # then use Termcolor for all colored text output
# print(Fore.BLACK + 'some red text')
# print(Fore.RED + 'some red text')
# print(Fore.GREEN + 'some red text')
# print(Fore.YELLOW + 'some red text')
# print(Fore.BLUE + 'some red text')
# print(Fore.CYAN + 'some red text')
# print(Fore.MAGENTA + 'some red text')
# print('---------------------------------')
# print(Fore.LIGHTBLACK_EX + 'some red text')
# print(Fore.LIGHTRED_EX + 'some red text')
# print(Fore.LIGHTGREEN_EX + 'some red text')
# print(Fore.LIGHTYELLOW_EX + 'some red text')
# print(Fore.LIGHTBLUE_EX + 'some red text')
# print(Fore.LIGHTCYAN_EX + 'some red text')
# print(Fore.LIGHTMAGENTA_EX + 'some red text')