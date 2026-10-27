"""
hCaptcha 打码 — captcha.run

Stripe Checkout hCaptcha sitekey: ec637546-e9b8-447a-ab81-b5fb6d228ab8
host: b.stripecdn.com

API 文档:
  HCaptcha:       https://captcharun.atlassian.net/wiki/spaces/captcharunnew/pages/463110515/HCaptcha
  HCaptchaStripe: https://captcharun.atlassian.net/wiki/spaces/captcharunnew/pages/592019457/HCaptchaStripe

用法:
    from solve_captcha import solve_stripe_hcaptcha
    token = solve_stripe_hcaptcha(
        page_url="https://checkout.stripe.com/c/pay/cs_live_...",
        api_key="your_captcha_run_key",
    )
"""

import os
import time
import requests
from typing import Optional
from urllib.parse import urlparse

STRIPE_SITEKEY = "ec637546-e9b8-447a-ab81-b5fb6d228ab8"
STRIPE_HOST = "b.stripecdn.com"
CAPTCHA_RUN_API = "https://api.captcha-run.com"


def solve_stripe_hcaptcha(
    page_url: str,
    api_key: str = None,
    rqdata: str = None,
    timeout: int = 120,
) -> Optional[str]:
    """
    解决 Stripe 的 hCaptcha，返回 token。

    Args:
        page_url: Stripe Checkout URL
        api_key: captcha.run API key（也可通过环境变量 CAPTCHA_RUN_KEY 设置）
        rqdata: 可选，从页面 hcaptcha 请求中提取，有则用 HCaptchaStripe（成功率更高）
        timeout: 超时秒数

    Returns:
        hCaptcha token（P1_eyJ... 格式），失败返回 None
    """
    _api_key = api_key or os.environ.get("CAPTCHA_RUN_KEY", "")
    if not _api_key:
        print("  [captcha] ERROR: captcha.run api_key not set")
        print("  [captcha] Set CAPTCHA_RUN_KEY env var or pass api_key parameter")
        return None

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {_api_key}",
    }

    if rqdata:
        # HCaptchaStripe — 专为 Stripe 优化，需要 rqdata
        payload = {
            "captchaType": "HCaptchaStripe",
            "siteKey": STRIPE_SITEKEY,
            "siteHost": STRIPE_HOST,
            "rqdata": rqdata,
        }
        print(f"  [captcha] Using HCaptchaStripe (rqdata={rqdata[:30]}...)")
    else:
        # 普通 HCaptcha
        parsed = urlparse(page_url)
        site_referer = f"{parsed.scheme}://{parsed.netloc}/"
        payload = {
            "captchaType": "HCaptcha",
            "siteKey": STRIPE_SITEKEY,
            "siteReferer": site_referer,
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
            "fallbackToActualUA": True,
        }
        print(f"  [captcha] Using HCaptcha (siteReferer={site_referer})")

    try:
        # 提交任务
        resp = requests.post(f"{CAPTCHA_RUN_API}/v2/tasks",
                             headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        task_id = data.get("taskId")
        if not task_id:
            print(f"  [captcha] ERROR: no taskId in response: {data}")
            return None
        print(f"  [captcha] Task submitted: {task_id}")

        # 轮询结果
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(3)
            r = requests.get(f"{CAPTCHA_RUN_API}/v2/tasks/{task_id}",
                             headers=headers, timeout=15)
            r.raise_for_status()
            result = r.json()
            status = result.get("status", "")

            if status == "Success":
                resp_data = result.get("response", {})
                # HCaptchaStripe 返回 token，HCaptcha 返回 gRecaptchaResponse
                token = resp_data.get("token") or resp_data.get("gRecaptchaResponse", "")
                if token:
                    print(f"  [captcha] ✅ Solved: {token[:40]}...")
                    return token
                print(f"  [captcha] ERROR: no token in response: {result}")
                return None

            elif status == "Fail":
                reason = result.get("reason", "unknown")
                print(f"  [captcha] ❌ Failed: {reason}")
                return None

            # status == "Working" → continue polling

        print(f"  [captcha] ❌ Timeout after {timeout}s")
        return None

    except Exception as e:
        print(f"  [captcha] ERROR: {e}")
        return None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Test captcha.run hCaptcha solver")
    parser.add_argument("--api-key", default=os.environ.get("CAPTCHA_RUN_KEY", ""), required=False)
    parser.add_argument("--url", default="https://checkout.stripe.com/", help="Stripe checkout URL")
    parser.add_argument("--rqdata", default="", help="Optional rqdata from page")
    args = parser.parse_args()

    if not args.api_key:
        print("ERROR: --api-key required or set CAPTCHA_RUN_KEY env var")
        exit(1)

    token = solve_stripe_hcaptcha(
        page_url=args.url,
        api_key=args.api_key,
        rqdata=args.rqdata or None,
    )
    if token:
        print(f"\n✅ Token: {token}")
    else:
        print("\n❌ Failed")
