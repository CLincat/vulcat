#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
from random import randint

banner_0 = '''
                  ___                   _____
  _    _  _   _   | |     ____   ____  [_____]
 | \  / /| | | |  | |    / ___) / _  ]   | |
  \ \/ / | (_/ |  | |__ ( (___ ( [_] |   | |
   \__/  (____ ]/[_____] \____) \____]/  [_]
'''

banner_1 = '''
                  ___                   _____
  _    _  _   _   | |     ____   ____  [_____]
 | \  / /| | | |  | |    / ___) / _  ]   | |
  \ \/ / | (_/ |  | |__ ( (___ ( [_] |   | | n_n
   \__/  (__･ ･}/[_____] \____) \____]/  [_](• •)/
'''

banner_2 = '''
                  ___                   _____
  _    _  _   _   | |     ____   ____  [_____]
 | \  / /| | | |  | | u_u/ ___) / _  ]   | |
  \ \/ / | (_/ |  | |_･ ･}(___ ( [_] |   | |
   \__/  (____ ]/[_____] \____) \_• •)/  [_]
'''

# banner_3 = '''
#                   ___                   _____
#   _    _  _   _   | |     ____   ____  [_____]
#  | \  / /| | | |  | |    / ___) / ･ ･}   | |
#   \ \/ / | (_/ |  | |__ ( (___ ( [_] |   | |
#    \__/  (____ ]/[_____] \_• •) \____]/  [_]
# '''

def banner():
   num = randint(0, 2)
   banner_x = eval('banner_' + str(num))
   print(color.red_ex(banner_x), end=color.reset('\n'))