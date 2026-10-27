"""
iCloud 邮箱接码 — 通过 HTTP API 获取验证码

支持两种账号文件格式（每行一条，`#` 开头为注释）：

  1. 邮箱 + 专属接码 API（推荐，如 icloudemail.txt）
     xxx@icloud.com----https://ima2.52dfd.top/api/v1/mailboxes/xxx@icloud.com/code?key=xxx

  2. 仅邮箱（如 accounts.txt，走 api798 公共接口）
     xxx@icloud.com

公共接码 API: http://api798.com/latest?email=xxx@icloud.com&auth_code=SSS888
专属接码 API: 直接 GET 该 URL，返回 JSON（实测结构）:
    成功: {"success": true, "code": "465456", "email": "...",
           "subject": "验证您的 AWS 构建者 ID 电子邮件地址",
           "message_id": "msg_...", "received_at": "2026-10-27T23:45:35+08:00",
           "icloud_in_at": "...", "icloud_out_at": "...", "inbox_at": "...",
           "written_at": "2026-10-27T23:45:47+08:00"}
    未收到: {"success": false, "code": "no_code", "message": "...", "retryable": true}
    错误:   {"success": false, "code": "invalid_api_key", "message": "...", "retryable": false}

    `peek=1` 返回最近一次缓存码（旧码），不带 peek 时只等待新事件。
    本工具用 peek 做 send-otp 前的旧码快照，再轮询等待 code 变化。
"""
import os
import re
import json
import time
import requests
import logging
from typing import Optional, Tuple
from urllib.parse import quote as url_quote
from file_lock import file_lock

log = logging.getLogger("kiro")

# 默认配置
DEFAULT_API_URL = "http://api798.com/latest"
DEFAULT_AUTH_CODE = "SSS888"
# 账号文件里邮箱与专属 API 的分隔符
LINE_SEP = "----"


def parse_account_line(line: str) -> Tuple[Optional[str], Optional[str]]:
    """解析一行账号数据 -> (email, api_url)；无效行返回 (None, None)"""
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None, None
    if LINE_SEP in line:
        email, _, api_url = line.partition(LINE_SEP)
    elif "\t" in line:
        email, _, api_url = line.partition("\t")
    elif "," in line:
        email, _, api_url = line.partition(",")
    else:
        email, api_url = line, ""
    email = email.strip()
    api_url = api_url.strip()
    if not email or "@" not in email:
        return None, None
    return email, (api_url or None)


class ICloudMailbox:
    """iCloud 接码（专属 API 优先，回退 api798 公共接口）"""

    def __init__(self, accounts_file: str = None, api_url: str = None,
                 auth_code: str = None, proxy: str = None, wait_ms: int = 10000):
        """
        Args:
            accounts_file: 邮箱列表文件路径（支持 `邮箱----专属API` 格式）
            api_url: 公共接码 API 地址（账号行没有专属 API 时使用）
            auth_code: 公共接码 API 认证码
            proxy: HTTP 代理（接码 API 默认直连，不使用该代理）
            wait_ms: 专属 API 长轮询等待毫秒数（0 = 不等待）
        """
        self.accounts_file = accounts_file or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "accounts.txt")
        self.api_url = api_url or DEFAULT_API_URL
        self.auth_code = auth_code or DEFAULT_AUTH_CODE
        self.proxy = proxy
        self.wait_ms = max(0, int(wait_ms or 0))
        self._current_email = None
        self._current_api_url = None    # 当前邮箱的专属接码 API
        self._url_map = {}              # email -> api_url（本实例取过的邮箱）
        self._pre_otp_code = None       # send-otp 之前的旧验证码
        self._pre_otp_received_at = ""  # 旧验证码的接收时间

    # ═══ 文件读写 ═══
    def _read_lines(self) -> list:
        """读取文件中的非空行（保留注释行，解析时再过滤）"""
        with open(self.accounts_file, 'r', encoding='utf-8') as f:
            return [l.rstrip("\r\n") for l in f if l.strip()]

    def test_connection(self) -> bool:
        """检查账号文件是否可用"""
        if not os.path.exists(self.accounts_file):
            print(f"  [iCloud] ERROR: {self.accounts_file} not found")
            return False
        try:
            lines = self._read_lines()
        except Exception as e:
            print(f"  [iCloud] ERROR: read {self.accounts_file} failed: {e}")
            return False
        valid = [parse_account_line(l) for l in lines]
        valid = [(e, u) for e, u in valid if e]
        if not valid:
            print(f"  [iCloud] ERROR: No valid emails in {self.accounts_file}")
            return False
        with_api = sum(1 for _, u in valid if u)
        print(f"  [iCloud] OK: {len(valid)} emails available "
              f"({with_api} with dedicated API, {len(valid) - with_api} via {self.api_url})")
        return True

    def get_email(self) -> str:
        """获取一个邮箱并从文件中删除（并发安全）"""
        with file_lock(self.accounts_file):
            lines = self._read_lines()
            idx = None
            for i, l in enumerate(lines):
                if parse_account_line(l)[0]:
                    idx = i
                    break
            if idx is None:
                raise RuntimeError("No available emails")

            line = lines[idx].strip()
            email, api_url = parse_account_line(line)
            self._current_email = email
            self._current_api_url = api_url
            self._url_map[email] = api_url

            # 删除被取走的那一行，其余行（含注释）原样保留
            keep_lines = [l for i, l in enumerate(lines) if i != idx]
            with open(self.accounts_file, 'w', encoding='utf-8') as f:
                for keep_line in keep_lines:
                    f.write(keep_line + '\n')
            remaining = sum(1 for l in keep_lines if parse_account_line(l)[0])

        kind = "dedicated API" if api_url else "public API"
        print(f"  [iCloud] Using: {email} [{kind}], remaining: {remaining}")
        return email

    def return_email(self, email: str = None):
        """将邮箱放回文件末尾（注册失败时调用，避免浪费邮箱，并发安全）"""
        email = email or self._current_email
        if not email:
            return
        # 用本实例记录过的专属 API 还原成 `邮箱----API` 行
        api_url = self._url_map.get(email)
        if api_url is None and email == self._current_email:
            api_url = self._current_api_url
        line = f"{email}{LINE_SEP}{api_url}" if api_url else email

        with file_lock(self.accounts_file):
            try:
                lines = self._read_lines()
            except Exception:
                lines = []
            exists = any(parse_account_line(l)[0] == email for l in lines)
            if not exists:
                lines.append(line)
            with open(self.accounts_file, 'w', encoding='utf-8') as f:
                for l in lines:
                    f.write(l + '\n')
        print(f"  [iCloud] Returned email: {email} (back to pool)")

    # ═══ 验证码 ═══
    def _request_url(self, peek: bool = True, wait_ms: int = 0) -> str:
        """构造取码 URL：有专属 API 直接拼参数，否则走公共 API"""
        if self._current_api_url:
            url = self._current_api_url
            params = []
            if peek:
                params.append("peek=1")
            if wait_ms and wait_ms > 0:
                params.append(f"wait_ms={int(wait_ms)}")
            if params:
                url += ("&" if "?" in url else "?") + "&".join(params)
            return url
        return f"{self.api_url}?email={url_quote(self._current_email or '')}&auth_code={self.auth_code}"

    def _fetch_code(self, peek: bool = True, wait_ms: int = 0) -> Tuple[Optional[str], str]:
        """请求一次接码接口 -> (code, received_at)"""
        if not self._current_email:
            return None, ""
        url = self._request_url(peek=peek, wait_ms=wait_ms)
        timeout = max(15, int(wait_ms / 1000) + 10) if wait_ms else 15
        try:
            resp = requests.get(url, timeout=timeout)
        except Exception as e:
            log.debug(f"  [iCloud] API error: {e}")
            return None, ""
        if resp.status_code != 200:
            log.debug(f"  [iCloud] API HTTP {resp.status_code}: {resp.text[:120]}")
            return None, ""
        return self._parse_response(resp.text)

    def create_otp_callback(self, timeout=300):
        """创建 OTP 回调 — 在 send-otp 之前先记录当前的旧验证码"""
        # 先获取当前 API 返回的验证码（旧的），用于后续忽略
        self._pre_otp_code, self._pre_otp_received_at = self._fetch_code(peek=True)
        print(f"  [iCloud] Pre-OTP code snapshot: {self._pre_otp_code or 'none'}")

        _self = self

        def callback():
            return _self.wait_for_code(timeout=timeout)

        return callback

    def get_current_code(self) -> str:
        """获取当前 API 返回的验证码（用于后续对比是否有新码）"""
        code, _ = self._fetch_code(peek=True)
        return code or ""

    def wait_for_code(self, timeout: int = 300, interval: float = 5.0) -> str:
        """
        轮询专属接码 API，等待一个与 send-otp 之前不同的新验证码。
        单次请求会带 wait_ms 长轮询，减少无效请求；旧验证码通过快照比对忽略。
        """
        if not self._current_email:
            raise RuntimeError("No email set, call get_email() first")

        print(f"  [iCloud] Waiting for OTP: {self._current_email}...")

        old_code = self._pre_otp_code or ""
        print(f"  [iCloud] Old code (to ignore): {old_code or 'none'}")

        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            # 长轮询时间不超过剩余等待时间
            wait_ms = min(self.wait_ms, int(remaining * 1000)) if self.wait_ms else 0
            code, received_at = self._fetch_code(peek=True, wait_ms=wait_ms)
            if code and code != old_code:
                print(f"  [iCloud] Found NEW code: {code}")
                return code

            remaining = deadline - time.time()
            if remaining <= 0:
                break
            time.sleep(min(interval, remaining))

        raise TimeoutError(f"[iCloud] OTP timeout ({timeout}s)")

    # ═══ 响应解析 ═══
    @staticmethod
    def _normalize_code(value) -> Optional[str]:
        """把各种写法归一成 6 位验证码；'no_code' 等非数字返回 None"""
        if value is None:
            return None
        m = re.search(r'(?<!\d)(\d{6})(?!\d)', str(value))
        return m.group(1) if m else None

    @classmethod
    def _parse_response(cls, text: str) -> Tuple[Optional[str], str]:
        """解析接码接口响应 -> (code, received_at)

        新平台返回 JSON（success/code/received_at），旧 api798 返回 HTML。
        """
        if not text:
            return None, ""

        raw = text.strip()

        # 1) JSON（专属 API）
        if raw.startswith("{"):
            try:
                data = json.loads(raw)
            except Exception:
                data = None
            if isinstance(data, dict):
                received_at = str(data.get("received_at") or data.get("created_at") or "")
                if data.get("success") is False:
                    return None, received_at
                for key in ("code", "primary_code", "otp", "verification_code"):
                    code = cls._normalize_code(data.get(key))
                    if code:
                        return code, received_at
                codes = data.get("codes")
                if isinstance(codes, list):
                    for item in codes:
                        if isinstance(item, dict):
                            item = item.get("code")
                        code = cls._normalize_code(item)
                        if code:
                            return code, received_at
                return None, received_at

        # 2) HTML（旧 api798）
        m = re.search(r'class=[^>]*code[^>]*>\s*(\d{6})\s*<', raw)
        if m:
            return m.group(1), ""

        # 3) 纯验证码
        if re.match(r'^\d{6}$', raw):
            return raw, ""

        # 4) 邮件正文
        m = re.search(r'(?:verification code|Your code|验证码)[^0-9]*(\d{6})', raw, re.IGNORECASE)
        if m:
            return m.group(1), ""

        return None, ""
