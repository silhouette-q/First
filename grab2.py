# -*- coding: utf-8 -*-
"""
JLU 研究生选课助手 grab2.py （按 xsxkapp 前端协议 1:1 复刻版）
=================================================================
协议来源：同款高校系统前端 courses.js / coursejsp.js 逐行分析（2026-09-09）

核心机制（与网页完全一致）：
  1. csrfToken     -> GET  xsxkHome/loadPublicInfo_course.do  (WIS_PUBLIC_INFO.csrfToken)
  2. 课程列表      -> POST xsxkCourse/loadXxxCourseInfo.do (datas 字段)
     通道 lx: 0=计划内 loadJhnCourseInfo   1=公选 loadGxkCourseInfo
              2=方案内 loadFanCourseInfo   3=跨专业域 loadKxkzykCourseInfo
              5=重修   loadCxCourseInfo(GET)
  3. 提交选课      -> POST xsxkCourse/choiceCourse.do {bjdm, lx, csrfToken}
     返回 code==0 失败(带msg)；否则 msg=xid(任务号，异步队列)
  4. 轮询结果      -> POST xsxkCourse/loadXkjgRes.do {xid, sfhqdqxkqqs}
     msg为空=仍在处理(最多30次)；msg非空 -> JSON{code:1成功/0失败,msg}
     dqxkqqs = 服务器当前排队数(高峰提示)
  5. 已选课程      -> GET  xsxkCourse/loadStdCourseInfo.do (results 字段)
  6. 退课          -> POST xsxkCourse/cancelCourse.do {bjdm, csrfToken}

"不耽误手动抢"设计：
  - 轮询节奏默认 3 秒/轮，和网页手动刷新同量级，不会挤爆你的会话
  - WebVPN Cookie 与你的浏览器互不干扰（各自独立 session）
  - 成功后立即停止该课程，不再发任何请求

用法：
  A. 首次配置（交互）：
     1) 浏览器登录 WebVPN -> 打开选课系统页面
     2) F12 -> Network -> 刷新 -> 任选一个请求 -> 复制请求头里整行 Cookie
     3) py grab2.py   按提示粘贴 Cookie/学号/密码，结尾选 y 保存
  B. 之后一键运行：
     py grab2.py     回车即按 grab_config.json 运行
  C. 定时开抢：配置里 at="2026-09-16 14:00:00"，提前启动挂着，到点自动抢
  D. 一键全选：配置里 pick="all"（或交互时输 a），列表内课程逐门自动提交
  E. 系统未开放：每 3 秒轮询等待（每轮显示状态），开放后自动进入抢课；
     轮次开放中但列表为空 = 已全部选完，提示后回车退出；wait_open=false 可关闭等待
  F. 会话恢复：选课系统会话过期 -> 自动重登；WebVPN 会话过期（JLU 登录有
     微信二次验证，无法自动登录）-> 提示手动贴新 Cookie，贴完自动继续并写回配置
  G. 轮次未开放：自动挂机探测等开放。配置 "open_at"（下次开放时间，启动时选 o 可直接
     设置）会挂机到开放前 open_lead 秒（默认 5 分钟）转 3 秒高频探测；未配置则按
     "probe_gap"（默认 10 秒）间隔探测。探测带时间戳与已等待时长；等待中会话过期自动重登
"""
import getpass
import json
import os
import re
import sys
import time

import requests

import des_jlu

# 深澜 WebVPN 会往响应中间注入 <script>var __vpn_hostname_data...</script> 配置块，
# 恰好可能切在 JSON 字符串中间导致 JSON 损坏，解析前必须剥掉
_VPN_INJECT_RE = re.compile(r'<script\b[^>]*>[\s\S]*?</script>', re.I)


def parse_json(text):
    """容错 JSON 解析：剥离 WebVPN 注入块 + 允许控制字符"""
    if '<script' in text:
        text = _VPN_INJECT_RE.sub('', text)
    return json.loads(text, strict=False)

# ========================= 配置 =========================
# WebVPN 加密前缀（校外用）。校园网内可改成 INNER_BASE 直连
DEFAULT_BASE = 'https://vpn.jlu.edu.cn/https/48714f71342f7a336d582f7e2857373746c660020384c4a9a4cc571c010ffc36'
INNER_BASE = 'https://yjs.jlu.edu.cn'
P = '/yjsxkapp/sys/xsxkapp'          # 应用路径
PAGE_SIZE = 500                       # 一次拉全部
# 批量提交间隔（秒）：多门课连续提交时错开，防瞬时并发触发限流
SUBMIT_GAP = 0.3
# loadXkjgRes 单次任务最多查询轮数（结果随盯守轮询每轮查一次）
MAX_POLL = 30
# 轮次未开放时：距 open_at 还剩多久转 3 秒高频探测（默认提前 5 分钟）
OPEN_LEAD = 300
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/139.0.0.0 Safari/537.36'
# =======================================================

CHANNELS = {
    '0': ('loadJhnCourseInfo.do',    '计划内课程'),
    '1': ('loadGxkCourseInfo.do',    '公选课'),
    '2': ('loadFanCourseInfo.do',    '方案内课程'),
    '3': ('loadKxkzykCourseInfo.do', '跨专业域课程'),
    '5': ('loadCxCourseInfo.do',     '重修课程'),
}


class CookieExpired(Exception):
    pass


class RoundNotOpen(Exception):
    """轮次未开放（服务器返回“暂未开放选课”）——登录态正常，等开放即可"""
    pass


def ts_url(url):
    """前端习惯：所有 .do 都带 _=时间戳 防缓存（已有参数则用 &）"""
    sep = '&' if '?' in url else '?'
    return f'{url}{sep}_={int(time.time() * 1000)}'


class XsxkClient:
    def __init__(self, base, cookie, username=None, password=None):
        self.base = base.rstrip('/')
        self.username = username
        self.password = password
        self.ocr = None
        self.referer = self.base + P + '/index.html'
        self.sess = requests.Session()
        self.sess.headers.update({
            'User-Agent': UA,
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': self.referer,
            'Origin': self.base.split('/https/')[0] if '/https/' in self.base else self.base,
        })
        if cookie:
            from urllib.parse import urlparse
            host = urlparse(self.base).netloc
            for part in cookie.split(';'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    self.sess.cookies.set(k.strip(), v.strip(), domain=host)
        self.sess.verify = False
        self.csrf = ''
        self.public_info = {}

    # ---------- 底层 ----------
    def _req(self, method, url, **kw):
        r = self.sess.request(method, url, timeout=20, allow_redirects=False,
                              headers={'Referer': self.referer}, **kw)
        # WebVPN: 普通请求 302->/login；Ajax 请求 200 + 过期JSON
        if r.status_code in (301, 302, 303, 307) and '/login' in r.headers.get('Location', ''):
            raise CookieExpired()
        body = r.text[:400] if r.text else ''
        if '您的会话已经过期' in body or ('"success"' in body and '会话' in body and '过期' in body):
            raise CookieExpired()
        if '未登录' in body:
            # 第三种过期形态：WebVPN 会话仍有效（请求穿透成功），
            # 但内网选课系统会话已失效 -> 走重登链（有密码则全自动重登）
            raise CookieExpired()
        if r.status_code != 200:
            raise RuntimeError(f'HTTP {r.status_code}: {body[:120]}')
        return r

    def _post(self, path, data=None):
        r = self._req('POST', ts_url(self.base + P + '/' + path), data=data or {})
        resp = parse_json(r.text)
        self._absorb(resp)
        return resp

    def _get(self, path):
        r = self._req('GET', ts_url(self.base + P + '/' + path))
        resp = parse_json(r.text)
        self._absorb(resp)
        return resp

    # ---------- 登录（全自动） ----------
    def _get_vtoken(self):
        r = self._get('login/4/vcode.do')
        if str(r.get('code')) == '1':
            return r['data']['token']
        raise RuntimeError('获取 vtoken 失败: ' + json.dumps(r, ensure_ascii=False)[:200])

    def login_with_retry(self, max_try=8):
        """vtoken -> 验证码OCR -> 登录。成功返回 True，验证码错自动重试"""
        if self.ocr is None:
            import ddddocr
            self.ocr = ddddocr.DdddOcr(show_ad=False)
        self.referer = self.base + P + '/index.html'
        for i in range(max_try):
            vtoken = self._get_vtoken()
            r = self._req('GET', ts_url(self.base + P + '/login/vcode/image.do?vtoken=' + vtoken))
            ctype = r.headers.get('Content-Type', '')
            if 'image' not in ctype:
                print('  [登录] 验证码图接口返回异常:', ctype, r.content[:120])
                time.sleep(1)
                continue
            code = ''.join(ch for ch in self.ocr.classification(r.content) if ch.isalnum())
            if not code:
                continue
            body = {'loginName': self.username,
                    'loginPwd': des_jlu.str_enc_simple(self.password),
                    'verifyCode': code,
                    'vtoken': vtoken}
            resp = self._post('login/check/login.do', body)
            c = str(resp.get('code'))
            if c == '1':
                print('  [登录] 成功（第 %d 次尝试）' % (i + 1))
                self.referer = self.base + P + '/course.html'
                return True
            if c == '3':
                continue  # 验证码错，换一张
            if c == '4':
                print('  [登录] 在线人数超限，等待重试...')
                time.sleep(5)
                continue
            if c == '2':
                raise RuntimeError('登录名或密码不正确（规则：学号+身份证后6位 或 学号+gsapp）')
            raise RuntimeError('登录失败: ' + json.dumps(resp, ensure_ascii=False)[:200])
        raise RuntimeError('验证码连续识别失败 %d 次' % max_try)

    # ---------- 协议接口 ----------
    def _absorb(self, resp):
        """服务端可能在任意响应里下发新 csrfToken（轮换机制），
        旧 token 提交会被拒“页面已过期”——响应里带了就跟进"""
        t = resp.get('csrfToken')
        if t:
            self.csrf = t

    def load_csrf(self, quiet=False):
        """GET loadPublicInfo_course.do -> csrfToken + 学生信息 + 流程信息"""
        info = self._get('xsxkHome/loadPublicInfo_course.do')
        self.public_info = info
        self.csrf = info.get('csrfToken', '')
        xs = info.get('xsMap') or {}
        lc = info.get('lcxxMap') or {}
        if not quiet:
            print(f"  登录者: {xs.get('XH', '?')} {xs.get('XM', '')}")
            print(f"  当前轮次: {lc.get('MC', '?')}")
            if lc.get('XKCL') is not None:
                cl = {'0': '可选可退', '1': '可选不可退', '2': '不可选可退'}.get(str(lc.get('XKCL')), str(lc.get('XKCL')))
                print(f"  选课策略: {cl}")
        if not self.csrf:
            msg = str(info.get('msg') or '')
            if '未开放' in msg:
                # 轮次未开放：登录态正常但不发 csrfToken，等开放即可
                raise RoundNotOpen(msg)
            raise RuntimeError('未拿到 csrfToken，返回内容: ' + json.dumps(info, ensure_ascii=False)[:300])
        return self.csrf

    def load_courses(self, lx, keyword='', page=1, kclb=''):
        """课程列表。lx 对应 CHANNELS。返回 (total, datas)"""
        if lx == '5':
            resp = self._get('xsxkCourse/loadCxCourseInfo.do')
            return len(resp.get('results', [])), resp.get('results', [])
        data = {'query_keyword': keyword, 'query_kkyx': '', 'query_kcfl': '',
                'query_kcbq': '', 'query_xqdm': '', 'query_skyydm': '',
                'query_sfct': '', 'query_sfym': '',
                'fixedAutoSubmitBug': '',
                'pageIndex': page, 'pageSize': PAGE_SIZE,
                'sortField': '', 'sortOrder': ''}
        if lx == '2':
            data['query_kclb'] = kclb or ''
        api = CHANNELS[lx][0]
        resp = self._post('xsxkCourse/' + api, data)
        # zeroGrid 协议: 数据在 datas，总数在 total
        datas = resp.get('datas') or resp.get('results') or []
        return resp.get('total', len(datas)), datas

    def choice_course(self, bjdm, lx):
        """提交选课。返回 xid 或抛 RuntimeError(带失败原因)"""
        d = {'bjdm': bjdm, 'lx': lx, 'csrfToken': self.csrf}
        resp = self._post('xsxkCourse/choiceCourse.do', d)
        code = resp.get('code')
        if code == 0:
            raise RuntimeError(resp.get('msg') or '未知失败')
        # code 非0: msg 即 xid，进入异步队列
        return resp.get('msg')

    def poll_once(self, xid, first=False):
        """查一次选课结果。返回 ('done', '选课成功') / ('fail', 原因) / ('wait', None=仍在处理)"""
        d = {'xid': xid, 'sfhqdqxkqqs': 1 if first else 0}
        resp = self._post('xsxkCourse/loadXkjgRes.do', d)
        dq = resp.get('dqxkqqs')
        if dq:
            try:
                dq = int(dq)
                if dq >= 200:
                    print(f'    [高峰] 服务器正在处理 {dq} 个请求，排队中...')
            except (TypeError, ValueError):
                pass
        msg = resp.get('msg')
        if msg:
            r = json.loads(msg) if isinstance(msg, str) else msg
            if r.get('code') == 1:
                return 'done', '选课成功'
            return 'fail', r.get('msg') or '未知原因'
        return 'wait', None

    def my_courses(self):
        """已选课程 results"""
        resp = self._get('xsxkCourse/loadStdCourseInfo.do')
        return resp.get('results', [])

    def cancel_course(self, bjdm):
        d = {'bjdm': bjdm, 'csrfToken': self.csrf}
        resp = self._post('xsxkCourse/cancelCourse.do', d)
        return resp.get('code') == 1, resp.get('msg', '')


# ========================= 交互辅助 =========================

def fmt_course(c):
    bjdm = c.get('BJDM', '?')
    name = f"{c.get('KCDM', '')} {c.get('KCMC', '')}"
    if c.get('BJMC'):
        name += f"({c['BJMC']})"
    teacher = c.get('RKJS', '')
    cap = f"{c.get('DQRS', 0)}/{c.get('KXRS', 0)}"
    full = '满' if c.get('DQRS', 0) >= c.get('KXRS', 0) and c.get('KXRS', 0) else ' '
    sched = (c.get('PKSJDDMS') or '')[:36]
    return f"[{bjdm}] {name} | {teacher} | {cap}{full} | {sched}"


def paste_cookie():
    print('粘贴 Cookie（一行，回车结束；直接回车=退出）:')
    cookie = input('> ').strip()
    return cookie


# ========================= 配置文件与批量模式 =========================
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'grab_config.json')


def load_config():
    """读取 grab_config.json（不存在返回 None）"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f'[!] 配置文件损坏（{e}），忽略之')
    return None


def save_config(cfg):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    print(f'[√] 配置已保存: {CONFIG_FILE}')


def dump_cookie(cli):
    """把会话当前 Cookie 拼回字符串（登录后服务端可能更新了 ticket）"""
    return '; '.join(f'{c.name}={c.value}' for c in cli.sess.cookies)


def relogin(cli, base, cfg=None):
    """会话过期恢复：先试内网自动重登；WebVPN 本身过期时引导贴新 Cookie
    （JLU WebVPN 登录有微信二次验证，无法全自动）。返回可用 cli 或 None"""
    if cli.username and cli.password:
        print('\n[!] 会话过期，自动重登选课系统...')
        for _ in range(2):
            try:
                cli.login_with_retry()
                cli.load_csrf()
                if cfg is not None:
                    cfg['cookie'] = dump_cookie(cli)
                    save_config(cfg)  # 最新 Cookie 写回配置
                return cli
            except RoundNotOpen:
                # 登录成功但轮次未开放（拿不到 csrfToken）——会话已建好，交回上层等开放
                print('[i] 登录成功，选课轮次未开放')
                return cli
            except CookieExpired:
                break  # WebVPN 会话问题，走贴 Cookie 流程
            except Exception as e:
                print(f'[!] 重登失败: {e or type(e).__name__}，重试...')
                time.sleep(2)
    print('\n[!] WebVPN 会话已过期：请在浏览器重新登录 WebVPN（需微信验证），')
    print('    然后 F12 -> Network -> 任选请求 -> 复制 Cookie 整行粘贴到这里（直接回车=放弃）')
    for _ in range(3):
        nc = paste_cookie()
        if not nc:
            return None
        ncli = XsxkClient(base, nc, cli.username, cli.password)
        try:
            if ncli.username and ncli.password:
                ncli.login_with_retry()  # 新 WebVPN 会话，内网会话未必已建立，直接自动登录
            ncli.load_csrf()
            if cfg is not None:
                cfg['cookie'] = dump_cookie(ncli)
                save_config(cfg)  # 新 Cookie 写回配置，下次直接可用
            return ncli
        except RoundNotOpen:
            # 登录成功但轮次未开放——新 Cookie 本身有效，写回配置后交回上层等开放
            print('[i] 新 Cookie 有效，选课轮次未开放')
            if cfg is not None:
                cfg['cookie'] = dump_cookie(ncli)
                save_config(cfg)
            return ncli
        except Exception as e:
            print(f'[!] 新 Cookie 登录失败: {e or type(e).__name__}，请重新复制粘贴')
    return None


def wait_until(at_str):
    """等到目标时刻（提前 10 秒返回用于预热）"""
    target = time.mktime(time.strptime(at_str, '%Y-%m-%d %H:%M:%S'))
    remain = target - time.time()
    if remain <= 0:
        print('[定时] 目标时刻已过，立即执行')
        return
    print(f'\n[定时] 目标时刻 {at_str}，还需等待 {int(remain)} 秒（提前 10 秒预热）')
    while True:
        remain = target - time.time()
        if remain <= 10:
            break
        time.sleep(min(20, remain - 10))
        left = int(target - time.time())
        if left % 60 < 20 and left > 60:
            print(f'  ...还差 {left} 秒')
    while time.time() < target - 10:
        time.sleep(0.2)
    print('[定时] 进入预热窗口')


def round_state(cli):
    """依据轮次开放起止时间（lcxxMap.KFKSSJ/KFJSSJ）判断状态：
    notopen(未开放)/open(开放中)/closed(已结束)/unknown"""
    lc = (getattr(cli, 'public_info', {}) or {}).get('lcxxMap') or {}
    kssj = lc.get('KFKSSJ') or ''
    jssj = lc.get('KFJSSJ') or ''
    try:
        t0 = time.mktime(time.strptime(kssj, '%Y-%m-%d %H:%M:%S'))
        t1 = time.mktime(time.strptime(jssj, '%Y-%m-%d %H:%M:%S'))
    except Exception:
        return 'unknown', kssj or jssj
    now = time.time()
    if now < t0:
        return 'notopen', kssj
    if now > t1:
        return 'closed', jssj
    return 'open', ''


def wait_for_open(cli, base, cfg=None):
    """轮次未开放：挂机探测直到开放（拿到 csrfToken）。
    配置 open_at=下次开放时间时，先静默等到开放前 60 秒再 3 秒高频探测；
    未配置则按 probe_gap（默认 10 秒）间隔探测。等待中会话过期走自动重登链。
    返回 (True, cli) 或 (False, cli)"""
    t_start = time.time()
    open_at = str((cfg or {}).get('open_at') or '').strip()
    t0 = None
    if open_at:
        try:
            t0 = time.mktime(time.strptime(open_at, '%Y-%m-%d %H:%M:%S'))
        except ValueError:
            print('[!] open_at 格式应为 2026-09-17 11:00:00，忽略该配置')
            open_at = ''
    if t0:
        try:
            lead = max(1, int(float((cfg or {}).get('open_lead')))) if (cfg or {}).get('open_lead') else OPEN_LEAD
        except (TypeError, ValueError):
            lead = OPEN_LEAD
        remain = t0 - lead - time.time()
        if remain > 0:
            lead_txt = f'{lead // 60} 分钟' if lead % 60 == 0 else f'{lead} 秒'
            print(f'[等待] 轮次未开放，预计 {open_at} 开放；挂机 {int(remain)} 秒后'
                  f'（提前 {lead_txt}）转 3 秒高频探测（Ctrl+C 可停）')
            time.sleep(remain)
        gap = 3
    else:
        raw = (cfg or {}).get('probe_gap')
        try:
            gap = max(1, int(float(raw))) if raw else 10
        except (TypeError, ValueError):
            gap = 10
        print('[提示] 未配置 open_at。知道开放时间的话在 grab_config.json 加 '
              '"open_at": "2026-09-17 11:00:00"，可挂机到开放前 1 分钟转 3 秒高频探测')
    print(f'[等待] 每 {gap} 秒探测一次开放状态（Ctrl+C 可停）')
    while True:
        try:
            cli.load_csrf(quiet=True)
            print(f'\n[√] 轮次已开放（{time.strftime("%H:%M:%S")}），进入选课流程')
            return True, cli
        except RoundNotOpen:
            w = int(time.time() - t_start)
            print(f'  [{time.strftime("%H:%M:%S")}] 探测：尚未开放（已等待 {w // 60}分{w % 60:02d}秒）...')
            time.sleep(gap)
        except CookieExpired:
            ncli = relogin(cli, base, cfg)
            if ncli is None:
                return False, cli
            cli = ncli
        except Exception as e:
            print(f'  [{time.strftime("%H:%M:%S")}] 探测异常: {e or type(e).__name__}，继续...')
            time.sleep(gap)


def refresh_ready(cli, base, cfg=None):
    """确保 csrfToken 可用：过期则重登、未开放则等开放。返回 cli 或 None（用户放弃）"""
    while True:
        try:
            cli.load_csrf(quiet=True)
            return cli
        except RoundNotOpen:
            ok, cli = wait_for_open(cli, base, cfg)
            if not ok:
                return None
        except CookieExpired:
            ncli = relogin(cli, base, cfg)
            if ncli is None:
                return None
            cli = ncli
            if cli.csrf:
                return cli
        except Exception:
            time.sleep(3)


def main():
    print('=' * 60)
    print(' JLU 研究生选课助手 v2.5 （配置预置 + 盯守抢课）')
    print('=' * 60)
    base = DEFAULT_BASE
    print('入口: WebVPN 模式（校园网内可改脚本顶部 INNER_BASE 直连）')

    cfg = load_config()
    if cfg:
        print(f"\n[配置] 学号={cfg.get('username', '?')} 通道={cfg.get('lx', '0')} "
              f"目标={'列表全部课程' if cfg.get('pick') == 'all' else (cfg.get('pick') or '交互选序号')} "
              f"定时={cfg.get('at') or '立即'}")
        c = input('回车=按配置运行 / e=重新配置 / o=设置开放时间（提前转高频探测）: ').strip().lower()
        if c == 'e':
            cfg = None
        elif c == 'o':
            oa = input('下次开放时间（2026-09-17 11:00:00，回车=不设置）: ').strip()
            if not oa:
                print('[i] 未输入，跳过设置（未开放时按 10 秒探测）')
            else:
                try:
                    time.strptime(oa, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    print(f'[!] 格式不对：{oa}（应为 2026-09-17 11:00:00），本次不设置')
                else:
                    cfg['open_at'] = oa
                    save_config(cfg)
                    print(f'[√] open_at={oa} 已保存：未开放时将挂机至临近开放'
                          f'（默认提前 5 分钟，可配 open_lead）转 3 秒高频探测')

    if cfg:
        cli = XsxkClient(base, cfg.get('cookie', ''),
                         cfg.get('username'), cfg.get('password'))
        ok = False
        try:
            cli.load_csrf()
            ok = True
        except CookieExpired:
            if not (cli.username and cli.password):
                print('[!] Cookie 已过期且配置无密码，无法自动重登（用 e 重新配置）')
                return
            print('[!] Cookie 已过期，走自动恢复链...')
        except RoundNotOpen as e:
            print(f'[i] 登录态正常，但选课轮次未开放：{e}')
            ok2, cli = wait_for_open(cli, base, cfg)
            if ok2:
                ok = True
            else:
                return
        except Exception as e:
            print(f'[!] 出错: {e or type(e).__name__}')
            return
        if not ok:
            # relogin 覆盖完整链：内网重登 -> WebVPN 自动登录 -> 贴 Cookie 兑底
            ncli = relogin(cli, base, cfg)
            if ncli is None:
                return
            cli = ncli
            if not cli.csrf:
                # 登录成功但轮次未开放（relogin 里拿不到 csrfToken）——挂机等开放
                ok2, cli = wait_for_open(cli, base, cfg)
                if not ok2:
                    return
        lx = cfg.get('lx') or '0'
        pick = cfg.get('pick') or ''
        at = cfg.get('at') or ''
    else:
        print('\n登录方式: 1=全自动登录（推荐，会话过期自动重登） 2=粘贴选课系统Cookie')
        mode = input('> ').strip() or '1'

        if mode == '2':
            cookie = paste_cookie()
            if not cookie:
                return
            cli = XsxkClient(base, cookie)
            while True:
                try:
                    cli.load_csrf()
                    break
                except RoundNotOpen:
                    oa = input('轮次未开放。预计开放时间（2026-09-17 11:00:00，回车=不知道，30 秒一探）: ').strip()
                    ok2, cli = wait_for_open(cli, base, {'open_at': oa})
                    if ok2:
                        break
                    return
                except CookieExpired:
                    print('\n[!] Cookie 已过期/无效，请重新从浏览器复制（F12 -> Network -> Cookie 整行）')
                    cookie = paste_cookie()
                    if not cookie:
                        return
                    cli = XsxkClient(base, cookie)
                except Exception as e:
                    print(f'[!] 出错: {e}，重试中...')
                    time.sleep(2)
        else:
            print('浏览器登录 WebVPN 后，F12 -> Network -> 刷新 -> 任选一个 vpn.jlu.edu.cn 请求 -> 复制 Cookie 整行')
            cookie = paste_cookie()
            if not cookie:
                return
            xh = input('学号: ').strip()
            pwd = getpass.getpass('选课系统密码（学号+身份证后6位 或 学号+gsapp，输入不回显）: ')
            if not xh or not pwd:
                print('[!] 学号或密码为空')
                return
            cli = XsxkClient(base, cookie, xh, pwd)
            while True:
                try:
                    cli.login_with_retry()
                    break
                except CookieExpired:
                    print('\n[!] WebVPN Cookie 无效，请重新复制')
                    cookie = paste_cookie()
                    if not cookie:
                        return
                    cli = XsxkClient(base, cookie, xh, pwd)
                except RuntimeError as e:
                    print(f'[!] {e}')
                    if '密码' in str(e):
                        return
                    print('    重试中...')
                    time.sleep(2)
                except Exception as e:
                    print(f'[!] 出错: {e}，重试中...')
                    time.sleep(2)
            try:
                cli.load_csrf()
            except RoundNotOpen:
                oa = input('轮次未开放。预计开放时间（2026-09-17 11:00:00，回车=不知道，30 秒一探）: ').strip()
                ok2, cli = wait_for_open(cli, base, {'open_at': oa})
                if not ok2:
                    return
            except Exception as e:
                print(f'[!] 登录后拉取信息失败: {e}')
                return

        # 交互模式：问通道 / 目标 / 定时 / 是否存配置
        print('\n可选课程通道:')
        for k, (_, nm) in CHANNELS.items():
            print(f'  {k} = {nm}')
        lx = input('选择通道 [0 计划内课程为默认]: ').strip() or '0'
        if lx not in CHANNELS:
            lx = '0'
        pick = input('抢课目标: 回车=稍后交互选序号 / a=列表全部课程自动选: ').strip().lower()
        if pick == 'a':
            pick = 'all'
        at = input('定时开抢（格式 2026-09-16 14:00:00，回车=立即）: ').strip()
        open_at = input('预计下次开放时间（可选，格式 2026-09-17 11:00:00，回车=不填）: ').strip()
        if input('\n保存为配置文件 grab_config.json（下次一键运行）? [y/N]: ').strip().lower() == 'y':
            new_cfg = {'cookie': dump_cookie(cli), 'username': cli.username or '',
                       'password': '', 'lx': lx, 'pick': pick, 'at': at, 'open_at': open_at}
            if cli.username and input('  同时保存选课系统密码明文以便全自动重登? [y/N]: ').strip().lower() == 'y':
                new_cfg['password'] = cli.password
                print('  （注意: 密码明文存于本机 grab_config.json，勿外传）')
            save_config(new_cfg)

    # ---- 定时等待 ----
    if at:
        wait_until(at)

    # ---- 拉列表（未开放时挂机轮询；开放中但列表空 = 已全部选完） ----
    print(f'\n拉取课程列表（{CHANNELS.get(lx, ("?", lx))[1]}）...')
    wait_open = bool(cfg.get('wait_open', True)) if cfg else True
    if wait_open:
        print('（系统未开放时每 3 秒轮询等待，Ctrl+C 可停）')
    datas = []
    total = 0
    poll_n = 0
    while True:
        try:
            total, datas = cli.load_courses(lx)
        except CookieExpired:
            ncli = relogin(cli, base, cfg)
            if ncli is None:
                return
            cli = ncli
            continue
        except Exception as e:
            if not wait_open:
                print(f'[!] 列表拉取失败: {e or type(e).__name__}')
                return
            total, datas = 0, []  # 等待模式下忽略瞬时错误
        if datas:
            break
        state, tstr = round_state(cli)
        if state == 'open':
            poll_n += 1
            print(f'  [{time.strftime("%H:%M:%S")}] 第 {poll_n} 次轮询：暂无课程可选——你已全部选完；'
                  f'有人退课/新课程出现会立即捕获，持续盯守中（Ctrl+C 可停）...')
            time.sleep(3)
            continue
        if state == 'closed':
            print(f'\n[!] 选课轮次已结束（{tstr}）。')
            input('按回车退出...')
            return
        # notopen / unknown：挂机等待
        if not wait_open:
            print(f'\n[!] 系统尚未开放（开放时间 {tstr or "?"}），wait_open=false 已配置为不等待，退出。')
            return
        poll_n += 1
        print(f'  [{time.strftime("%H:%M:%S")}] 第 {poll_n} 次轮询：未开放，等待中（开放时间 {tstr or "?"}）...')
        time.sleep(3)
    print(f'共 {total} 门')
    for i, c in enumerate(datas):
        print(f'{i:3d} {fmt_course(c)}')

    # ---- 确定目标 ----
    if pick == 'all':
        targets = [(c.get('BJDM'), f"{c.get('KCDM')} {c.get('KCMC')}({c.get('BJMC', '')})") for c in datas]
        print(f'\n[一键全选] 将依次提交 {len(targets)} 门课程（逐门等结果，失败不影响后续）')
    else:
        picks = pick if (cfg and pick) else input('\n输入要抢的序号（多个用逗号分隔，回车放弃）: ').strip()
        if not picks:
            return
        targets = []
        for s in str(picks).split(','):
            try:
                idx = int(s.strip())
                c = datas[idx]
                targets.append((c.get('BJDM'), f"{c.get('KCDM')} {c.get('KCMC')}({c.get('BJMC', '')})"))
            except (ValueError, IndexError):
                print(f'  跳过无效序号: {s}')
        if not targets:
            return

    print(f'\n将抢 {len(targets)} 门，持续盯守直到全部选完（每 3 秒刷新列表）。')
    print('满员的课会一直盯着——有人退课释放名额就立即自动提交；Ctrl+C 可随时停止。')
    name_of = dict(targets)
    results = {b: 'pending' for b, _ in targets}
    fails = {b: 0 for b, _ in targets}
    # 满员等名额不计失败次数；只对提交后的业务失败限重试次数
    max_retry = 3 if pick == 'all' else 10 ** 9
    round_n = 0
    tickets = []  # 已提交、服务器处理中：(bjdm, name, xid)，每轮开头查一次结果，不阻塞新提交
    try:
        while True:
            round_n += 1

            # 1) 顺带查上一轮提交的结果（每轮只查一次，没出的下轮继续 —— 结果慢慢等）
            if tickets:
                still = []
                for j, (bjdm, name, xid) in enumerate(tickets):
                    try:
                        st, msg = cli.poll_once(xid, first=(j == 0))
                        if st == 'done':
                            print(f'  >>> 成功！{name} 已选上 <<<')
                            results[bjdm] = 'done'
                        elif st == 'fail' and results[bjdm] == 'pending':
                            fails[bjdm] += 1
                            if fails[bjdm] <= max_retry:
                                print(f'  >>> 失败: {msg} —— 继续盯守重试')
                            else:
                                print(f'  >>> 失败: {msg} —— 已达重试上限，放弃该门')
                                results[bjdm] = f'fail:{msg[:40]}'
                        else:
                            still.append((bjdm, name, xid))  # 仍在服务器队列里，下轮再查
                    except CookieExpired:
                        still.append((bjdm, name, xid))  # 会话过期，留给下面拉列表统一 relogin
                    except Exception as e:
                        print(f'  查询异常: {e or type(e).__name__} —— 下轮再查')
                        still.append((bjdm, name, xid))
                tickets = still

            # 2) 拉最新列表
            try:
                total, datas = cli.load_courses(lx)
            except CookieExpired:
                ncli = relogin(cli, base, cfg)
                if ncli is None:
                    print('\n已停止。')
                    break
                cli = ncli
                continue
            except Exception as e:
                print(f'  [{time.strftime("%H:%M:%S")}] 列表拉取失败: {e or type(e).__name__}，稍后重试')
                time.sleep(3)
                continue

            in_list = {c.get('BJDM'): c for c in datas}

            # 2) 目标已从可选列表消失 = 已选上
            for bjdm, name in targets:
                if results[bjdm] == 'pending' and bjdm not in in_list:
                    results[bjdm] = 'done'
                    print(f'  >>> {name} 已从可选列表消失（应已选上）<<<')

            # 3) 一键全选模式：列表新出现的课自动纳入盯守（如盯守中自己退课重抢）
            if pick == 'all':
                for c in datas:
                    b = c.get('BJDM')
                    if b and b not in results:
                        nm = f"{c.get('KCDM')} {c.get('KCMC')}({c.get('BJMC', '')})"
                        targets.append((b, nm))
                        results[b] = 'pending'
                        fails[b] = 0
                        print(f'  [新目标] {nm} 出现在列表，纳入盯守')

            # 4) 分类：提交处理中的跳过（防重复提交）；有余量的立即抢；满员的盯守待余量
            carrying = {b for b, _, _ in tickets}
            todo, watching = [], []
            for bjdm, name in targets:
                if results[bjdm] != 'pending' or bjdm not in in_list:
                    continue
                if bjdm in carrying:
                    watching.append((bjdm, name))
                    continue
                c = in_list[bjdm]
                try:
                    full = int(c.get('DQRS') or 0) >= int(c.get('KXRS') or 0)
                except (TypeError, ValueError):
                    full = False
                (watching if full else todo).append((bjdm, name))

            # 5) 轮次结束 / 全部完成 → 收尾
            state, tstr = round_state(cli)
            if state == 'closed':
                print(f'\n[!] 选课轮次已结束（{tstr}），停止盯守。')
                break
            if not tickets and all(v != 'pending' for v in results.values()):
                break  # 所有目标都已选上/放弃，且没有在途请求

            # 6) 批量提交本轮有余量的课（每门间隔 SUBMIT_GAP 防瞬时并发）。
            #    提交完立即返回，不等结果 —— 结果由下一轮开头顺带查询，绝不阻塞新提交
            #    提交前刷新 csrfToken：服务端会轮换 token，旧 token 会被拒“页面已过期”
            stopped = False
            if todo:
                ncli = refresh_ready(cli, base, cfg)
                if ncli is None:
                    print('\n已停止。')
                    break
                cli = ncli
            for bjdm, name in todo:
                try:
                    print(f'\n[{time.strftime("%H:%M:%S")}] 提交选课: {name}')
                    xid = cli.choice_course(bjdm, lx)
                    print(f'  已入队列 xid={xid}（结果下轮盯守时查询）')
                    tickets.append((bjdm, name, xid))
                except CookieExpired:
                    ncli = relogin(cli, base, cfg)
                    if ncli is None:
                        stopped = True
                        break
                    cli = ncli
                except RuntimeError as e:
                    if '过期' in str(e):
                        # token 失效信号：可恢复错误，刷新后重试，不计失败次数
                        print(f'  提交被拒（token 已轮换）: {e} —— 刷新 token 后重试')
                        ncli = refresh_ready(cli, base, cfg)
                        if ncli is None:
                            stopped = True
                            break
                        cli = ncli
                    else:
                        fails[bjdm] += 1
                        if fails[bjdm] <= max_retry:
                            print(f'  提交被拒: {e} —— 继续盯守重试')
                        else:
                            print(f'  提交被拒: {e} —— 已达重试上限，放弃该门')
                            results[bjdm] = f'refused:{str(e)[:40]}'
                except Exception as e:
                    print(f'  异常: {e} —— 稍后重试')
                if len(todo) > 1:
                    time.sleep(SUBMIT_GAP)
            if stopped:
                print('\n已停止。')
                break

            # 7) 盯守状态（每轮可见）
            parts = []
            if watching:
                show = '; '.join(n for _, n in watching[:3])
                if len(watching) > 3:
                    show += f' 等 {len(watching)} 门'
                parts.append(f'满员待余量 —— {show}')
            if tickets:
                parts.append(f'已提交待结果 {len(tickets)} 门')
            if parts:
                print(f'  [{time.strftime("%H:%M:%S")}] 第 {round_n} 轮盯守：{"；".join(parts)}')
            time.sleep(3)
    except KeyboardInterrupt:
        print('\n已停止。')

    # 总结 + 已选确认
    print('\n===== 结果 =====')
    for bjdm, name in targets:
        mark = '成功' if results[bjdm] == 'done' else '未成功'
        print(f'  [{mark}] {name}  {"" if results[bjdm] == "done" else results[bjdm]}')
    try:
        print('\n当前已选课程:')
        for c in cli.my_courses():
            print('  ', fmt_course(c))
    except Exception:
        pass
    if results and all(v == 'done' for v in results.values()):
        print('\n[√] 全部选完！')
    input('\n按回车退出...')


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    import urllib3
    urllib3.disable_warnings()
    main()
