# -*- coding: utf-8 -*-
"""
吉林大学本科选课网(icourses.jlu.edu.cn)抢课脚本 —— raw.py 交互改造版

依赖安装（清华镜像）:
    py -m pip install requests pycryptodome ddddocr -i https://pypi.tuna.tsinghua.edu.cn/simple

使用:
    py grab.py

流程: 输入学号密码 -> 自动识别验证码登录 -> 选批次 -> 展示收藏课程 ->
      8线程轮询抢课(自动循环, 直到全部抢到或 Ctrl+C 退出)
"""

import base64
import json
import os
import sys
import threading
import time
from copy import deepcopy

import requests
import urllib3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

# ---- 验证码 OCR（装不上 ddddocr 时自动降级为手动输入）----
try:
    import ddddocr
    OCR = ddddocr.DdddOcr(show_ad=False)
except Exception as e:
    print(f"[提示] ddddocr 不可用({e}), 将改为手动输入验证码")
    OCR = None

WorkThreadCount = 8
BASE = 'https://icourses.jlu.edu.cn'
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36')

HEADERS = {
    'Host': 'icourses.jlu.edu.cn',
    'Origin': BASE,
    'Referer': BASE + '/xsxk/profile/index.html',
    'User-Agent': UA,
}


def pkcs7padding(data, block_size=16):
    if type(data) != bytearray and type(data) != bytes:
        raise TypeError("仅支持 bytearray/bytes 类型!")
    pl = block_size - (len(data) % block_size)
    return data + bytearray([pl for i in range(pl)])


def aes_ecb_b64(password, key):
    """AES-128-ECB + PKCS7 + base64, 与网页前端加密一致"""
    data = bytes(pkcs7padding(password.encode('utf-8')))
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return base64.b64encode(enc.update(data) + enc.finalize()).decode()


class iCourses:
    mutex = threading.Lock()

    def __init__(self):
        self.aeskey = b''
        self.loginname = ''
        self.password = ''
        self.captcha = ''
        self.uuid = ''
        self.token = ''
        self.batchId = ''
        self.s = requests.session()
        self.is_login = False
        self.favorite = None
        self.select = None
        self.batchlist = None
        self.current = {}
        self.error_code = 0
        self.try_if_capacity_full = True

    def safe_request(self, method, url, **kwargs):
        """永不放弃的请求包装器, 网络错误持续重试"""
        while True:
            try:
                if method.lower() == 'get':
                    return self.s.get(url, timeout=10, **kwargs)
                return self.s.post(url, timeout=10, **kwargs)
            except Exception as e:
                print(f"请求错误: {e}, 正在重试...")
                time.sleep(0.5)

    # ---------- 登录 ----------
    def _get_aeskey(self):
        html = self.safe_request('get', BASE + '/', headers=HEADERS, verify=False).text
        start = html.find('"', html.find('loginVue.loginForm.aesKey')) + 1
        end = html.find('"', start)
        return html[start:end].encode('utf-8')

    def _fetch_captcha(self):
        data = json.loads(self.safe_request(
            'post', BASE + '/xsxk/auth/captcha', headers=HEADERS, verify=False).text)
        self.uuid = data['data']['uuid']
        captcha = data['data']['captcha']
        img = base64.b64decode(captcha[captcha.find(',') + 1:])
        if OCR is not None:
            self.captcha = OCR.classification(img)
        else:
            with open('captcha.png', 'wb') as f:
                f.write(img)
            try:
                os.startfile('captcha.png')
            except Exception:
                pass
            self.captcha = input('请打开 captcha.png 输入验证码: ').strip()

    def login(self, username, password):
        """无限重试登录"""
        while True:
            try:
                self.aeskey = self._get_aeskey()
                self.loginname = username
                self.password = aes_ecb_b64(password, self.aeskey)

                self._fetch_captcha()

                payload = {
                    'loginname': self.loginname,
                    'password': self.password,
                    'captcha': self.captcha,
                    'uuid': self.uuid,
                }
                response = json.loads(self.safe_request(
                    'post', BASE + '/xsxk/auth/login',
                    headers=HEADERS, data=payload, verify=False).text)

                if response['code'] == 200 and response['msg'] == '登录成功':
                    self.token = response['data']['token']
                    student = response['data']['student']
                    print('登录成功!')
                    print('=' * 64)
                    print(f"\t学号:   {student['XH']}")
                    print(f"\t姓名:   {student['XM']}")
                    print(f"\t专业:   {student['ZYMC']}")
                    print('=' * 64)
                    self.batchlist = student['electiveBatchList']
                    for i, c in enumerate(self.batchlist):
                        print(f"[{i}] {c['name']}")
                        print(f"    {c['beginTime']} ~ {c['endTime']}")
                    print('=' * 64)
                    self.is_login = True
                    return True
                print(f"登录失败: {response['msg']}, 0.5s 后重试...")
                time.sleep(0.5)
            except Exception as e:
                print(f"登录过程出错: {e}, 重试中...")
                time.sleep(0.5)

    # ---------- 批次 ----------
    def choose_batch(self):
        """交互式选择批次"""
        while True:
            idx = input(f'请输入批次序号(0~{len(self.batchlist) - 1}): ').strip()
            if idx.isdigit() and int(idx) < len(self.batchlist):
                self.setbatchId(int(idx))
                return
            print('输入有误, 请重新输入')

    def setbatchId(self, idx):
        while True:
            try:
                self.batchId = self.batchlist[idx]['code']
                payload = {'batchId': self.batchId}
                response = json.loads(self.safe_request(
                    'post', BASE + '/xsxk/elective/user',
                    headers=HEADERS, data=payload, verify=False).text)
                if response['code'] != 200:
                    print("设置批次失败, 重试...")
                    time.sleep(0.5)
                    continue
                c = self.batchlist[idx]
                print(f"已选择批次: {c['name']} ({c['beginTime']} ~ {c['endTime']})")
                url = BASE + '/xsxk/elective/grablessons?batchId=' + self.batchId
                self.safe_request('get', url,
                                  headers={**HEADERS, 'Authorization': self.token},
                                  verify=False)
                return
            except Exception as e:
                print(f"设置批次时出错: {e}, 重试中...")
                time.sleep(0.5)

    # ---------- 课程 ----------
    def get_select(self):
        while True:
            try:
                headers = {**HEADERS, 'Authorization': self.token,
                           'batchId': self.batchId,
                           'Referer': BASE + '/xsxk/elective/grablessons?batchId=' + self.batchId}
                response = json.loads(self.safe_request(
                    'post', BASE + '/xsxk/elective/select',
                    headers=headers, verify=False).text)
                if response['code'] == 200:
                    self.select = response['data']
                    return
                print(f"获取已选课程失败: {response['msg']}")
                time.sleep(0.5)
            except Exception as e:
                print(f"获取已选课程时出错: {e}, 重试中...")
                time.sleep(0.5)

    def get_favorite(self):
        while True:
            try:
                headers = {**HEADERS, 'Authorization': self.token,
                           'batchId': self.batchId,
                           'Referer': BASE + '/xsxk/elective/grablessons?batchId=' + self.batchId}
                response = json.loads(self.safe_request(
                    'post', BASE + '/xsxk/sc/clazz/list',
                    headers=headers, verify=False).text)
                if response['code'] == 200:
                    self.favorite = response['data']
                    return
                print(f"获取收藏课程失败: {response['msg']}")
                time.sleep(0.5)
            except Exception as e:
                print(f"获取收藏课程时出错: {e}, 重试中...")
                time.sleep(0.5)

    def select_favorite(self, ClassType, ClassId, SecretVal):
        while True:
            try:
                headers = {**HEADERS, 'Authorization': self.token,
                           'batchId': self.batchId,
                           'Referer': BASE + '/xsxk/elective/grablessons?batchId=' + self.batchId}
                payload = {'clazzType': ClassType, 'clazzId': ClassId,
                           'secretVal': SecretVal}
                return json.loads(self.safe_request(
                    'post', BASE + '/xsxk/sc/clazz/addxk',
                    headers=headers, data=payload, verify=False).text)
            except Exception as e:
                print(f"选课请求出错: {e}, 重试中...")
                time.sleep(0.5)

    def workThread(self, clazzType, clazzId, SecretVal, Name):
        tmp = deepcopy(self)
        while True:
            try:
                response = tmp.select_favorite(clazzType, clazzId, SecretVal)
                code = response['code']
                msg = response['msg']

                self.mutex.acquire()
                try:
                    if self.current.get(clazzId) == 'doing':
                        if code == 200:
                            print(f'>>> [成功] {Name}')
                            self.current[clazzId] = 'done'
                            self.mutex.release()
                            break
                        elif code == 500:
                            if msg == '该课程已在选课结果中':
                                print(f'>>> [已选] {Name}')
                                self.current[clazzId] = 'done'
                                self.mutex.release()
                                break
                            if msg == '本轮次选课暂未开始':
                                self.mutex.release()
                                time.sleep(1)
                                continue
                            if msg == '课容量已满':
                                self.mutex.release()
                                if self.try_if_capacity_full:
                                    time.sleep(0.5)
                                    continue
                                break
                            print(f'[{Name}] {msg}')
                            self.mutex.release()
                            continue
                        elif code == 401:
                            print('会话过期(401), 将重新登录...')
                            self.error_code = 401
                            self.mutex.release()
                            break
                        else:
                            print(f'[{code}] 失败, 重试中...')
                            self.mutex.release()
                            continue
                    else:
                        self.mutex.release()
                        break
                except Exception:
                    if self.mutex.locked():
                        self.mutex.release()
                    raise
            except Exception as e:
                print(f"工作线程出错: {e}, 重试中...")
                if self.mutex.locked():
                    self.mutex.release()
                time.sleep(0.5)

    def PrintSelect(self):
        print('=' * 20 + ' 我的已选课程 ' + '=' * 20)
        if self.select:
            for item in self.select:
                print(f"教师: {item['SKJS']:<8} 课程: {item['KCM']}")

    def PrintFavorite(self):
        print('=' * 20 + ' 待抢收藏课程 ' + '=' * 20)
        if self.favorite:
            for item in self.favorite:
                print(f"教师: {item['SKJS']:<8} 课程: {item['KCM']}  "
                      f"类型: {item.get('teachingClassType', '?')}")
        print('=' * 48)

    def FuckMyFavorite(self):
        """一轮并发抢课(阻塞到本轮全部线程结束)"""
        while True:
            try:
                self.get_favorite()
                if self.favorite is None:
                    continue
                self.current = {}
                threads = {}
                for item in self.favorite:
                    key = item['JXBID']
                    threads[key] = []
                    self.mutex.acquire()
                    self.current[key] = 'doing'
                    self.mutex.release()
                    args = (item['teachingClassType'], item['JXBID'],
                            item['secretVal'], item['KCM'])
                    for _ in range(WorkThreadCount):
                        t = threading.Thread(target=self.workThread, args=args)
                        threads[key].append(t)
                        t.start()
                for key in threads:
                    for t in threads[key]:
                        t.join()
                print('本轮抢课结束, 检查结果...')
                return
            except Exception as e:
                print(f"抢课过程出错: {e}, 重试中...")
                time.sleep(0.5)

    def all_done(self):
        return bool(self.current) and all(v == 'done' for v in self.current.values())


def main():
    print('=' * 48)
    print('   吉林大学本科选课网 自动抢课 (交互版)')
    print('=' * 48)
    print('使用前请先在浏览器上把想抢的课【收藏】好!\n')

    username = input('学号: ').strip()
    try:
        password = getpass_hide('密码(输入不回显): ')
    except Exception:
        password = input('密码: ').strip()

    while True:
        a = iCourses()
        while not a.is_login:
            a.login(username, password)

        a.choose_batch()
        a.get_favorite()
        a.PrintFavorite()
        if not a.favorite:
            print('!! 收藏列表为空: 请先去选课网站上把要抢的课加入收藏, 再运行本脚本')
            return

        input('确认无误后按回车开始抢课 (Ctrl+C 退出)... ')

        try:
            while not a.all_done():
                a.FuckMyFavorite()
                if a.error_code == 401:
                    print('会话过期, 重新登录...')
                    a.is_login = False
                    a.error_code = 0
                    while not a.is_login:
                        a.login(username, password)
                    continue
                a.get_select()
                a.PrintSelect()
                if a.all_done():
                    print('\n*** 全部课程抢到了, 完事! ***')
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            print('\n已手动停止抢课')
            return

        again = input('继续盯着下一批次? (y/N): ').strip().lower()
        if again != 'y':
            break


def getpass_hide(prompt):
    import getpass
    return getpass.getpass(prompt)


if __name__ == '__main__':
    main()
