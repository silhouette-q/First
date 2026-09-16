# -*- coding: utf-8 -*-
"""临时：列出已选课程各自的实时余量，用于挑选安全的退课测试对象"""
import io, sys, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r'd:\JLU\抢课助手')
import urllib3
urllib3.disable_warnings()
import grab2

COOKIE = 'show_fast=1; heartbeat=1; show_faq=0; show_vpn=1; wengine_vpn_ticketvpn_jlu_edu_cn=3e9c57a4f754c884; refresh=1'
cli = grab2.XsxkClient(grab2.DEFAULT_BASE, COOKIE)
cli.load_csrf()

mine = cli.my_courses()
print(f'已选 {len(mine)} 门，匹配本轮开课列表中的实时余量:\n')

# 拉全部课程（tab100），分页
form = {'query_keyword': '', 'query_kkyx': '', 'query_kcfl': '',
        'query_kcbq': '', 'query_xqdm': '', 'query_skyydm': '',
        'query_sfct': '', 'query_sfym': '', 'fixedAutoSubmitBug': '',
        'pageIndex': 1, 'pageSize': 2000, 'sortField': '', 'sortOrder': ''}
resp = cli._post('xsxkCourse/loadLcAllCourseInfo.do', form)
allc = resp.get('datas') or []
idx = {c.get('BJDM'): c for c in allc}
print(f'本轮开课共 {resp.get("total")} 门，按 BJDM 匹配:\n')

for m in mine:
    bjdm = m.get('BJDM')
    c = idx.get(bjdm)
    if c:
        kxrs, dqrs = c.get('KXRS', 0), c.get('DQRS', 0)
        free = kxrs - dqrs
        risk = '安全' if free >= 5 else ('尚可' if free >= 1 else '危险!')
        print(f"  [{risk}] 余 {free:3d} ({dqrs}/{kxrs})  {m.get('KCDM')} {m.get('KCMC')}({m.get('BJMC','')}) {m.get('RKJS','')}")
    else:
        print(f"  [未匹配] {m.get('KCDM')} {m.get('KCMC')}({m.get('BJMC','')}) BJDM={bjdm}")
