"""
LuckMail 邮箱适配器 - 对接 LuckMailSdk-Python
通过 LuckMail 接码平台获取临时邮箱并自动接收验证码

用法:
    mailbox = LuckMailMailbox(base_url="...", api_key="...")
    otp_callback = mailbox.create_otp_callback(project_code="kiro")
    code = otp_callback()  # 阻塞等待验证码
"""

import sys
import os
import time
import re

from luckmail import LuckMailClient, APIError, AuthError, NetworkError, TimeoutError


class LuckMailMailbox:
    """
    LuckMail 邮箱服务适配器

    封装 LuckMailSdk，提供与 KiroRegister 兼容的 otp_callback 接口。

    Args:
        base_url: LuckMail API 地址，如 https://your-domain.com
        api_key: LuckMail API Key（在平台「个人设置」页面生成）
        api_secret: API Secret（可选，HMAC 签名验证）
        project_code: 项目编码（用于创建接码订单）
        email_type: 邮箱类型（可选）
        domain: 指定邮箱域名（可选）
        otp_timeout: 验证码等待超时（秒），默认 300
        otp_interval: 轮询间隔（秒），默认 3.0
    """

    DEFAULT_BASE_URL = "https://mails.luckyous.com"

    def __init__(
        self,
        api_key: str,
        base_url: str = None,
        api_secret: str = None,
        project_code: str = "kiro",
        email_type: str = None,
        domain: str = None,
        otp_timeout: int = 300,
        otp_interval: float = 3.0,
        use_hmac: bool = False,
    ):
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.api_key = api_key
        self.project_code = project_code
        self.email_type = email_type
        self.domain = domain
        self.otp_timeout = otp_timeout
        self.otp_interval = otp_interval
        self._last_email = None

        self.client = LuckMailClient(
            base_url=self.base_url,
            api_key=api_key,
            api_secret=api_secret,
            use_hmac=use_hmac,
        )

    def get_email(self) -> str:
        """
        获取一个临时邮箱地址（创建接码订单）。

        Returns:
            邮箱地址字符串
        """
        body = {"project_code": self.project_code}
        if self.email_type:
            body["email_type"] = self.email_type
        if self.domain:
            body["domain"] = self.domain

        order = self.client.user.create_order(**body)
        self._last_email = order.email_address
        self._last_order_no = order.order_no
        return order.email_address

    def wait_for_code(self, order_no: str = None, timeout: int = None) -> str:
        """
        等待并返回验证码。

        Args:
            order_no: 订单号（默认使用最后一次 get_email 创建的订单）
            timeout: 超时秒数（默认使用初始化时的 otp_timeout）

        Returns:
            验证码字符串

        Raises:
            TimeoutError: 超时未收到验证码
        """
        if not order_no:
            order_no = getattr(self, '_last_order_no', None)
        if not order_no:
            raise RuntimeError("No active order, call get_email() first")

        timeout = timeout or self.otp_timeout
        result = self.client.user.wait_for_code(
            order_no,
            timeout=timeout,
            interval=self.otp_interval,
        )

        if result.status == "success" and result.verification_code:
            return result.verification_code

        raise TimeoutError(
            f"OTP wait failed: status={result.status}, "
            f"timeout={timeout}s"
        )

    def create_otp_callback(self, timeout: int = None):
        """
        创建与 KiroRegister 兼容的 otp_callback 函数。

        该函数会先获取邮箱，然后阻塞等待验证码并返回。

        Args:
            timeout: 验证码等待超时（秒）

        Returns:
            callable: 调用时返回验证码字符串的函数

        Usage:
            otp_cb = mailbox.create_otp_callback(timeout=120)
            code = otp_cb()  # 阻塞直到收到验证码
        """
        _timeout = timeout or self.otp_timeout
        _self = self

        def callback():
            return _self.wait_for_code(timeout=_timeout)

        return callback

    def create_and_wait(self, timeout: int = None):
        """
        一站式方法：获取邮箱 + 等待验证码。

        Args:
            timeout: 验证码等待超时（秒）

        Returns:
            tuple: (email, code)
        """
        email = self.get_email()
        code = self.wait_for_code(timeout=timeout)
        return email, code

    def test_connection(self) -> bool:
        """测试 API 连接是否正常"""
        try:
            info = self.client.user.get_user_info()
            print(f"  [LuckMail] Connected, user: {info.username}, balance: {info.balance}")
            return True
        except AuthError as e:
            print(f"  [LuckMail] Auth failed: {e}")
            return False
        except Exception as e:
            print(f"  [LuckMail] Connection failed: {e}")
            return False
