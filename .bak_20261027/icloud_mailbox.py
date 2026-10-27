"""
iCloud 邮箱接码 — 通过 HTTP API 获取验证码

接码 API: http://api798.com/latest?email=xxx@icloud.com&auth_code=SSS888
accounts.txt 格式: 每行一个邮箱地址
"""
import os
import time
import re
import requests
import logging
from typing import Optional
from urllib.parse import quote as url_quote
from file_lock import file_lock

log = logging.getLogger("kiro")

# 默认配置
DEFAULT_API_URL = "http://api798.com/latest"
DEFAULT_AUTH_CODE = "SSS888"


class ICloudMailbox:
    """iCloud 接码（通过 HTTP API）"""

    def __init__(self, accounts_file: str = None, api_url: str = None,
                 auth_code: str = None, proxy: str = None):
        """
        Args:
            accounts_file: 邮箱列表文件路径
            api_url: 接码 API 地址
            auth_code: API 认证码
            proxy: HTTP 代理（接码 API 可能不需要）
        """
        self.accounts_file = accounts_file or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "accounts.txt")
        self.api_url = api_url or DEFAULT_API_URL
        self.auth_code = auth_code or DEFAULT_AUTH_CODE
        self.proxy = proxy
        self._current_email = None
        self._pre_otp_code = None  # send-otp 之前的旧验证码

    def test_connection(self) -> bool:
        """测试连接"""
        if not os.path.exists(self.accounts_file):
            print(f"  [iCloud] ERROR: {self.accounts_file} not found")
            return False
        with open(self.accounts_file, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip()]
        if not lines:
            print(f"  [iCloud] ERROR: No emails in {self.accounts_file}")
            return False
        print(f"  [iCloud] OK: {len(lines)} emails available")
        return True

    def get_email(self) -> str:
        """获取一个邮箱并从文件中删除（并发安全）"""
        with file_lock(self.accounts_file):
            with open(self.accounts_file, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip()]
            if not lines:
                raise RuntimeError("No available emails")

            self._current_email = lines[0]

            # 删除第一行
            with open(self.accounts_file, 'w', encoding='utf-8') as f:
                for line in lines[1:]:
                    f.write(line + '\n')

        print(f"  [iCloud] Using: {self._current_email}, remaining: {len(lines)-1}")
        return self._current_email

    def return_email(self, email: str = None):
        """将邮箱放回文件末尾（注册失败时调用，避免浪费邮箱，并发安全）"""
        email = email or self._current_email
        if not email:
            return
        with file_lock(self.accounts_file):
            with open(self.accounts_file, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip()]
            # 避免重复
            if email not in lines:
                lines.append(email)
            with open(self.accounts_file, 'w', encoding='utf-8') as f:
                for line in lines:
                    f.write(line + '\n')
        print(f"  [iCloud] Returned email: {email} (back to pool)")

    def create_otp_callback(self, timeout=300):
        """创建 OTP 回调 — 在 send-otp 之前先记录当前的旧验证码"""
        # 先获取当前 API 返回的验证码（旧的）
        self._pre_otp_code = self.get_current_code()
        print(f"  [iCloud] Pre-OTP code snapshot: {self._pre_otp_code or 'none'}")
        
        _self = self

        def callback():
            return _self.wait_for_code(timeout=timeout)

        return callback

    def get_current_code(self) -> str:
        """获取当前 API 返回的验证码（用于后续对比是否有新码）"""
        if not self._current_email:
            return ""
        try:
            url = f"{self.api_url}?email={url_quote(self._current_email)}&auth_code={self.auth_code}"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                code = self._extract_code(resp.text.strip())
                return code or ""
        except:
            pass
        return ""

    def wait_for_code(self, timeout: int = 300, interval: float = 5.0) -> str:
        """
        通过 API 轮询获取验证码
        逻辑：等待 API 返回一个与 send-otp 之前不同的新验证码
        """
        if not self._current_email:
            raise RuntimeError("No email set, call get_email() first")

        print(f"  [iCloud] Waiting for OTP: {self._current_email}...")

        # 记录 send-otp 之前的旧验证码
        old_code = self._pre_otp_code or ""
        print(f"  [iCloud] Old code (to ignore): {old_code or 'none'}")

        # 等待新邮件到达
        time.sleep(10)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                url = f"{self.api_url}?email={url_quote(self._current_email)}&auth_code={self.auth_code}"
                resp = requests.get(url, timeout=15)

                if resp.status_code == 200:
                    text = resp.text.strip()
                    code = self._extract_code(text)
                    if code and code != old_code:
                        print(f"  [iCloud] Found NEW code: {code}")
                        return code

            except Exception as e:
                log.debug(f"  [iCloud] API error: {e}")

            time.sleep(interval)

        raise TimeoutError(f"[iCloud] OTP timeout ({timeout}s)")

    @staticmethod
    def _extract_code(text: str) -> Optional[str]:
        """从 API 响应（HTML）中提取验证码
        
        API 返回 HTML 页面，验证码在 <div class="code" ...>XXXXXX</div> 中
        """
        if not text:
            return None
        
        # 优先从 HTML class 包含 "code" 的元素中提取
        m = re.search(r'class=[^>]*code[^>]*>\s*(\d{6})\s*<', text)
        if m:
            return m.group(1)
        
        # 如果不是 HTML，直接就是 6 位数字
        stripped = text.strip()
        if re.match(r'^\d{6}$', stripped):
            return stripped
        
        # 从 AWS 验证码邮件正文中提取
        m = re.search(r'(?:verification code|Your code)[^0-9]*(\d{6})', text, re.IGNORECASE)
        if m:
            return m.group(1)
        
        return None
