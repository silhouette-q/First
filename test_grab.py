# -*- coding: utf-8 -*-
"""
test_grab.py —— grab2.py 零风险测试脚本
=========================================
测什么（全程不退课、不产生任何选课副作用）：
  [1] 登录链路（自动登录 或 Cookie）
  [2] csrfToken / 学生信息 / 选课轮次
  [3] 计划内课程列表（lx=0，校准 datas 字段）
  [4] 已选课程（loadStdCourseInfo，校准 results 字段）
  [5] 选课提交链路：对你【已选过的课程】重复提交一次
      —— 系统必返失败(如"已选该课程")，验证 csrf/表单/队列全链路，无副作用
跑完把全部输出发给助手即可。
"""
import sys

import grab2
from grab2 import (CookieExpired, XsxkClient, DEFAULT_BASE, paste_cookie)
import getpass
import json
import time


def step(name):
    print(f'\n===== [{name}] =====')


def main():
    print('JLU 选课脚本零风险测试')
    base = DEFAULT_BASE

    print('\n登录方式: 1=全自动登录（学号+密码） 2=粘贴选课系统Cookie')
    mode = input('> ').strip() or '1'

    if mode == '2':
        cookie = paste_cookie()
        if not cookie:
            print('未输入 Cookie，退出')
            return
        cli = XsxkClient(base, cookie)
        cli.load_csrf()
    else:
        print('浏览器登录 WebVPN 后，F12 -> Network -> 刷新 -> 任选一个 vpn.jlu.edu.cn 请求 -> 复制 Cookie 整行')
        cookie = paste_cookie()
        if not cookie:
            return
        xh = input('学号: ').strip()
        pwd = getpass.getpass('选课系统密码（输入不回显）: ')
        cli = XsxkClient(base, cookie, xh, pwd)
        cli.login_with_retry()
        cli.load_csrf()

    # [3] 计划内课程列表
    step('3 计划内课程列表 lx=0')
    total, datas = cli.load_courses('0')
    print(f'总数(total字段): {total}，本次返回条数: {len(datas)}')
    if datas:
        print('第一条完整 JSON（字段校准用）:')
        print(json.dumps(datas[0], ensure_ascii=False, indent=1)[:1200])
        print('\n前 5 门预览:')
        for i, c in enumerate(datas[:5]):
            print(f'{i} {grab2.fmt_course(c)}')
    else:
        print('[!] 列表为空！')

    # [4] 已选课程
    step('4 已选课程 loadStdCourseInfo')
    mine = cli.my_courses()
    print(f'已选 {len(mine)} 门')
    for c in mine:
        print(f"  [BJDM={c.get('BJDM')}] {c.get('KCDM')} {c.get('KCMC')}"
              f"({c.get('BJMC', '')}) {c.get('RKJS', '')} BYBZ={c.get('BYBZ')}")

    # [5] 重复选测试
    step('5 选课提交链路测试（对已选课程重复提交，预期失败，无副作用）')
    if not mine:
        print('[跳过] 没有已选课程可供测试')
    else:
        target = mine[0]
        bjdm = target.get('BJDM')
        name = f"{target.get('KCDM')} {target.get('KCMC')}"
        print(f'对已选课程 {name} (BJDM={bjdm}) 重复提交选课(lx=0)...')
        try:
            xid = cli.choice_course(bjdm, '0')
            print(f'  返回 xid={xid}（进入异步队列），轮询最终结果...')
            ok, msg = cli.poll_result(xid)
            print(f'  轮询结果: ok={ok}, msg={msg!r}')
            print('  （若 msg 提示"已选/重复"等 -> 链路完全正常）')
        except Exception as e:
            print(f'  提交返回: {e}')
            print('  （若提示"已选该课程/请勿重复选"等 -> 链路完全正常）')

    step('测试完成')
    print('把上面全部输出复制发给助手，用于最终校准。')


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    import urllib3
    urllib3.disable_warnings()
    main()
