"""
从 kiro-credentials.json 直接调起 Kiro Pro 订阅支付
注意‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️ 
此脚本适用于Kiro buildID free号直接开pro

对谷歌号适用性未知
具体自测
😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡
😡不要拿谷歌号开

拿freeKiro开 有概率封free号
😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡😡

‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️‼️
只拿「新鲜」Stripe 链接（不写 CDK）——过期 checkout 时用同一条凭证再跑一次即可:
    python quick_subscribe.py 5
    python quick_subscribe.py 5 --open
    python quick_subscribe.py 5 --fresh-name        # 文件名带时间戳，不覆盖旧 payment_*.json

用法（完整）:
    python quick_subscribe.py                    # 第 0 条账号，仅获取支付 URL
    python quick_subscribe.py 7                  # 第 7 条账号（100 个号时用来轮询）
    python quick_subscribe.py --open             # 第 0 条 — 成功后用默认浏览器打开完整 Stripe 链接
    python quick_subscribe.py 7 --open           # 指定条目 + 打开浏览器（避免手动复制被 # 截断）
    python quick_subscribe.py <CDK码>            # 第 0 条 + 自动支付（CDK 非纯数字）
    python quick_subscribe.py 7 <CDK码>          # 指定账号 + 支付（勿把 --open 与 CDK 混在一个位置）

结账 URL 获取顺序（与 Edge 无痕网页对齐）:
  1) app.kiro.dev — KiroWebPortalService / Smithy RPC v2 CBOR
     GetAvailableSubscriptionPlans → GenerateSubscriptionManagementUrl
  2) 失败则回退 q.us-east-1 — listAvailableSubscriptions → CreateSubscriptionToken

环境变量:
  QUICK_SUBSCRIBE_CW_ONLY=1  — 跳过 Portal，只用 CodeWhisperer（调试用）
  YESCAPTCHA_API_KEY=<YesCaptcha Client Key> — 带 CDK 走 stripe_pay 时自动求解 hCaptcha（打码）

「协议支付」在此项目里即：Portal 生成 Stripe URL + Playwright(stripe_pay)
  调用 EFunCard 兑卡填表提交；Invisible hCaptcha / 勾选后触发的校验用 YesCaptcha 取 token 注入。
  Client Key 只放环境变量，勿写入仓库或在聊天明文长期暴露。

PowerShell:
  $env:YESCAPTCHA_API_KEY="你在 YesCaptcha 控制台的密钥"
  python quick_subscribe.py 4 YOUR_CDK

cards.779.chat 虚拟卡替代 EFun：
  $env:CARD_PROVIDER="cards779"
  $env:CARDS779_COOKIE="从浏览器复制的完整 Cookie（勿入库）"
  python quick_subscribe.py 4 R20260510030613400666362

依赖: cbor2；CDK 自动支付还需 playwright、captcha_solver(stripe_pay 会调)、httpx。
"""
import asyncio
import base64
import json
import os
import re
import secrets
import sys
import time
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path

import requests

CODEWHISPERER_ENDPOINT = "https://q.us-east-1.amazonaws.com"
PORTAL_ORIGIN = "https://app.kiro.dev"
PORTAL_RPC = PORTAL_ORIGIN + "/service/KiroWebPortalService/operation/"
SSO_OIDC_ENDPOINT = "https://oidc.{region}.amazonaws.com"

# 与 kiro_subscribe / 抓包一致：BuilderId 与 Google 不同帐号体系，混用则无 0 刀或报错
PROFILE_ARN_BY_PROVIDER = {
    "BuilderId": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
    "Github": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
    "GitHub": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
    "Google": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
}

# 与 edge HAR 中 GenerateSubscriptionManagementUrl 请求的 subscriptionType 一致
PREFERRED_PROMO_SUBSCRIPTION_TYPE = "Q_DEVELOPER_STANDALONE_PRO"

CRED_FILE = Path(__file__).parent / "kiro-credentials.json"


def captcha_config_for_stripe_pay():
    """stripe_pay.auto_pay(captcha_config=...) — 仅从环境读取，不写死第三方 Key"""
    key = os.environ.get("YESCAPTCHA_API_KEY", "").strip()
    if key:
        return {"yescaptcha_key": key}
    return {}


def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    tags = {"info": "INFO", "ok": " OK ", "warn": "WARN", "err": "ERR "}
    line = f"[{ts}] [{tags.get(level, level)}] {msg}"
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        print(line.encode(enc, errors="replace").decode(enc, errors="replace"))
    except Exception:
        print(line.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))


def _http_session():
    try:
        from curl_cffi.requests import Session

        s = Session(impersonate="chrome131")
        return s
    except ImportError:
        return requests.Session()


def resolve_profile_arn(creds):
    """单条凭证上的 profileArn 优先，否则按 provider 选（与抓包 / IDE 一致）"""
    arn = creds.get("profileArn") or creds.get("profile_arn")
    if arn:
        return arn
    prov = (creds.get("provider") or "BuilderId").strip()
    return PROFILE_ARN_BY_PROVIDER.get(
        prov, PROFILE_ARN_BY_PROVIDER["BuilderId"]
    )


def idp_for_provider(provider: str) -> str:
    """门户 Cookie Idp，与 app.kiro.dev 一致"""
    p = (provider or "BuilderId").strip().lower()
    if p == "google":
        return "Google"
    if p == "github":
        return "Github"
    return "BuilderId"


def _extract_csrf_from_html(html: str):
    if not html:
        return None
    m = re.search(
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)',
        html,
        re.I,
    )
    if m:
        return m.group(1)
    m = re.search(
        r'content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']',
        html,
        re.I,
    )
    if m:
        return m.group(1)
    return None


def init_portal_session(access_token, idp, extra_cookies=None):
    """
    用 Session 访问 /home、/account/usage，从 HTML meta 或 Set-Cookie 收齐
    csrf-token、UserId（与真实浏览器一致；自造 CSRF 会导致 Generate 401）。
    """
    jar = {"AccessToken": access_token, "Idp": idp}
    if extra_cookies and isinstance(extra_cookies, dict):
        jar.update(
            {k: v for k, v in extra_cookies.items() if isinstance(v, str)}
        )
    if cookies_complete(jar):
        return jar

    from requests.utils import add_dict_to_cookiejar

    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
    auth_h = {"Authorization": f"Bearer {access_token}"}

    sess = requests.Session()
    add_dict_to_cookiejar(
        sess.cookies, {k: v for k, v in jar.items() if v}
    )

    for path in ("/home", "/account/usage"):
        log(f"Portal: GET {path} 拉取 session / CSRF…", "info")
        resp = sess.get(
            f"{PORTAL_ORIGIN}{path}",
            headers={
                "User-Agent": ua,
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                ),
                **auth_h,
            },
            timeout=25,
            verify=False,
            allow_redirects=True,
        )
        if resp.status_code >= 400:
            log(f"Portal GET {path} HTTP {resp.status_code}", "warn")
        csrf_html = _extract_csrf_from_html(resp.text or "")
        if csrf_html:
            jar["csrf-token"] = csrf_html
            log("Portal: 从 HTML 取得 csrf-token", "ok")
            break

    merged = {k: v for k, v in jar.items() if v}
    for c in sess.cookies:
        dom = c.domain or ""
        if "kiro.dev" in dom or not dom:
            merged[c.name] = c.value

    if merged.get("csrf-token"):
        jar["csrf-token"] = merged["csrf-token"]

    if not merged.get("csrf-token"):
        merged["csrf-token"] = base64.b64encode(secrets.token_bytes(24)).decode()
        log("Portal: 无服务端 CSRF，自生成（GenerateSubscriptionManagementUrl 可能 401）", "warn")

    merged.update(jar)
    return merged


def cookies_complete(jar):
    return bool(jar.get("csrf-token") and jar.get("UserId"))


def _portal_error_snippet(resp, limit=160):
    ct = (resp.headers.get("content-type") or "").lower()
    if "cbor" in ct or "octet-stream" in ct:
        return resp.content[:limit].hex()
    return (resp.text or "")[:limit]


def portal_kiro_rpc(operation, payload, cookies, access_token):
    """Smithy RPC v2 CBOR — 与 Edge / HAR 一致"""
    try:
        import cbor2
    except ImportError:
        log("未安装 cbor2，无法调 Portal（pip install cbor2）", "err")
        return None

    url = PORTAL_RPC + operation
    body = cbor2.dumps(payload)
    s = _http_session()

    cookie_keys = (
        "AccessToken",
        "RefreshToken",
        "Idp",
        "UserId",
        "kiro-visitor-id",
        "awsccc",
        "csrf-token",
    )
    cookie_str = "; ".join(
        f"{k}={cookies[k]}"
        for k in cookie_keys
        if cookies.get(k)
    )
    visitor_id = cookies.get(
        "kiro-visitor-id",
        f"{int(time.time() * 1000)}-{secrets.token_hex(6)}",
    )
    user_id = cookies.get("UserId", "")
    csrf = cookies.get("csrf-token", "")

    headers = {
        "Content-Type": "application/cbor",
        "Accept": "application/cbor",
        "smithy-protocol": "rpc-v2-cbor",
        "Authorization": f"Bearer {access_token}",
        "x-csrf-token": csrf,
        "x-kiro-visitorid": visitor_id,
        "x-kiro-userid": user_id,
        "x-amz-user-agent": (
            "aws-sdk-js/1.0.0 ua/2.1 os/Windows lang/js md/browser#Chromium_131 m/N,M,E"
        ),
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1; max=1",
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "origin": PORTAL_ORIGIN,
        "referer": f"{PORTAL_ORIGIN}/account/usage",
        "cookie": cookie_str,
    }

    log(f"Portal RPC: {operation}", "info")
    resp = s.post(url, data=body, headers=headers, timeout=30, verify=False)
    if resp.status_code != 200:
        snip = _portal_error_snippet(resp)
        log(f"Portal {operation} HTTP {resp.status_code} — {snip}", "err")
        return None

    ct = resp.headers.get("content-type", "")
    if "cbor" in ct:
        try:
            return cbor2.loads(resp.content)
        except Exception as e:
            log(f"Portal CBOR 解码失败: {e}", "err")
            return None
    try:
        return resp.json()
    except Exception:
        return {"_raw": resp.text[:500]}


def select_subscription_type(plans):
    """从套餐列表选 Pro，优先 Q_DEVELOPER_STANDALONE_PRO"""
    if not plans:
        return None
    all_types = [p.get("qSubscriptionType", "") for p in plans]
    log(f"  套餐类型: {all_types[:8]}{'…' if len(all_types) > 8 else ''}", "info")
    if PREFERRED_PROMO_SUBSCRIPTION_TYPE in all_types:
        log(f"  选用: {PREFERRED_PROMO_SUBSCRIPTION_TYPE}", "ok")
        return PREFERRED_PROMO_SUBSCRIPTION_TYPE
    for p in plans:
        st = p.get("qSubscriptionType", "")
        if "PRO" in st.upper() and "PLUS" not in st.upper() and "POWER" not in st.upper():
            return st
    for p in plans:
        st = p.get("qSubscriptionType", "")
        if "FREE" not in st.upper():
            return st
    return None


def get_payment_url_portal(access_token, profile_arn, creds):
    """与 Edge 无痕网页同路径：Portal CBOR → Stripe URL"""
    if os.environ.get("QUICK_SUBSCRIBE_CW_ONLY") == "1":
        return None

    try:
        import cbor2  # noqa: F401
    except ImportError:
        log("跳过 Portal（无 cbor2）", "warn")
        return None

    provider = (creds or {}).get("provider") or "BuilderId"
    idp = idp_for_provider(provider)
    extra = (creds or {}).get("kiroCookies")
    jar = init_portal_session(access_token, idp, extra)

    plans_data = portal_kiro_rpc(
        "GetAvailableSubscriptionPlans",
        {"profileArn": profile_arn},
        jar,
        access_token,
    )
    if not plans_data or not isinstance(plans_data, dict):
        return None

    plans = plans_data.get("subscriptionPlans") or []
    log(f"Portal: 获取到 {len(plans)} 个套餐", "ok")
    sub_type = select_subscription_type(plans)
    if not sub_type:
        log("Portal: 未选出套餐", "err")
        return None
    log(f"Portal 选中套餐: {sub_type}", "ok")

    result = portal_kiro_rpc(
        "GenerateSubscriptionManagementUrl",
        {
            "subscriptionType": sub_type,
            "profileArn": profile_arn,
        },
        jar,
        access_token,
    )
    if not result or not isinstance(result, dict):
        return None
    url = result.get("encodedVerificationUrl", "")
    if not url:
        log(f"Portal 响应无 encodedVerificationUrl: {str(result)[:200]}", "err")
        return None

    log("Portal 支付 URL 获取成功", "ok")
    return {
        "payment_url": url,
        "subscription_type": sub_type,
        "status": result.get("status", ""),
        "source": "portal",
    }


def refresh_idc_token(client_id, client_secret, refresh_token, region="us-east-1"):
    """用 refreshToken 换取 accessToken (BuilderId/IdC 认证)"""
    url = SSO_OIDC_ENDPOINT.format(region=region) + "/token"
    body = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "refreshToken": refresh_token,
        "grantType": "refresh_token",
    }
    try:
        resp = _http_session().post(url, json=body, timeout=30, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "accessToken": data.get("accessToken"),
                "refreshToken": data.get("refreshToken"),
                "expiresIn": data.get("expiresIn", 3600),
                "idToken": data.get("idToken", ""),
            }
        else:
            log(f"Token 刷新失败: HTTP {resp.status_code} - {resp.text[:200]}", "err")
            return None
    except Exception as e:
        log(f"Token 刷新异常: {e}", "err")
        return None


def _headers(access_token):
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "x-amz-target": "com.amazonaws.codewhisperer",
        "x-amz-user-agent": "aws-sdk-js/1.0.0 ua/2.1 os/Windows lang/js md/browser#Chromium_131",
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1; max=3",
    }


def get_payment_url_codewhisperer(access_token, profile_arn):
    """q.us-east-1 JSON API（回退路径）"""
    session = _http_session()
    log("CodeWhisperer: 查询可用套餐…", "info")
    resp = session.post(
        f"{CODEWHISPERER_ENDPOINT}/listAvailableSubscriptions",
        json={"profileArn": profile_arn},
        headers=_headers(access_token),
        timeout=30,
        verify=False,
    )
    if resp.status_code != 200:
        log(f"查询套餐失败: HTTP {resp.status_code}", "err")
        return None

    data = resp.json()
    plans = data.get("subscriptionPlans", [])
    log(f"CodeWhisperer: 获取到 {len(plans)} 个套餐", "ok")

    sub_type = select_subscription_type(plans)
    if not sub_type:
        log("未找到可用套餐", "err")
        return None

    log(f"CodeWhisperer 选中套餐: {sub_type}", "ok")

    log("创建订阅 Token…", "info")
    resp = session.post(
        f"{CODEWHISPERER_ENDPOINT}/CreateSubscriptionToken",
        json={
            "provider": "STRIPE",
            "subscriptionType": sub_type,
            "profileArn": profile_arn,
            "clientToken": str(uuid.uuid4()),
        },
        headers=_headers(access_token),
        timeout=30,
        verify=False,
    )
    if resp.status_code != 200:
        log(f"创建 Token 失败: HTTP {resp.status_code}", "err")
        return None

    result = resp.json()
    url = result.get("encodedVerificationUrl", "")
    status = result.get("status", "")
    if not url:
        log("响应中无支付 URL", "err")
        return None

    log(f"CodeWhisperer 支付 URL 获取成功 (status={status})", "ok")
    return {
        "payment_url": url,
        "subscription_type": sub_type,
        "status": status,
        "source": "codewhisperer",
    }


def get_payment_url(access_token, profile_arn, creds=None):
    """先 Portal（对齐 Edge），失败再 CodeWhisperer"""
    p = get_payment_url_portal(access_token, profile_arn, creds or {})
    if p:
        return p
    log("回退 CodeWhisperer CreateSubscriptionToken…", "warn")
    return get_payment_url_codewhisperer(access_token, profile_arn)


def load_creds(index=0):
    if not CRED_FILE.exists():
        log(f"找不到凭证文件: {CRED_FILE}", "err")
        return None
    try:
        raw = json.loads(CRED_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            n = len(raw)
            if index < 0 or index >= n:
                log(f"索引越界: {index}（共 {n} 条）", "err")
                return None
            log(f"使用凭证第 {index + 1} 条（共 {n} 条）", "info")
            return raw[index]
        return raw
    except Exception as e:
        log(f"读取凭证失败: {e}", "err")
        return None


def parse_cli_account_index_and_cdk():
    """
    无参数 -> (0, '')
    1 个参数: 纯数字 -> (n, '')；否则 (0, cdk)
    2+ -> (int(args[0]), args[1])

    --open / --fresh-name 占位符从 argv 中剔除。
    """
    argv = [
        a
        for a in sys.argv[1:]
        if a not in ("--open", "--fresh-name")
    ]
    open_browser = "--open" in sys.argv[1:]
    args = argv
    if not args:
        return 0, "", open_browser
    if len(args) == 1:
        if args[0].isdigit():
            return int(args[0]), "", open_browser
        return 0, args[0], open_browser
    if not args[0].isdigit():
        log("两个参数时第一个必须是账号索引（非负整数），例如: python quick_subscribe.py 7 <CDK>", "err")
        sys.exit(1)
    return int(args[0]), args[1], open_browser


def main():
    print("=" * 50)
    print("  Kiro 快速订阅支付")
    print("=" * 50)
    print()

    account_idx, cdk, open_stripe = parse_cli_account_index_and_cdk()
    creds = load_creds(account_idx)
    if not creds:
        sys.exit(1)

    email = creds.get("email", "未知")
    access_token = creds.get("accessToken", "")
    refresh_token = creds.get("refreshToken", "")
    client_id = creds.get("clientId", "")
    client_secret = creds.get("clientSecret", "")
    region = creds.get("region", "us-east-1")
    provider = creds.get("provider", "")
    subscription = creds.get("subscription", "未知")

    print(f"  账号: {email}")
    print(f"  认证方式: {provider}")
    print(f"  当前套餐: {subscription}")
    print()

    # 没有 accessToken，尝试用 refreshToken 换取
    if not access_token and refresh_token and client_id and client_secret:
        log("凭证中无 accessToken，尝试用 refreshToken 换取...", "info")
        result = refresh_idc_token(client_id, client_secret, refresh_token, region)
        if result and result.get("accessToken"):
            access_token = result["accessToken"]
            log("Token 刷新成功!", "ok")
        else:
            log("Token 刷新失败", "err")
            sys.exit(1)

    if not access_token:
        log("凭证中缺少 accessToken 且无法刷新", "err")
        sys.exit(1)

    profile_arn = resolve_profile_arn(creds)
    log(f"profileArn: …{profile_arn[-24:]}", "info")

    sub_info = get_payment_url(access_token, profile_arn, creds)
    if not sub_info:
        log("获取支付链接失败", "err")
        sys.exit(1)

    print()
    print("=" * 50)
    src = sub_info.get("source", "")
    print(f"  渠道: {src}")
    print(f"  目标套餐: {sub_info['subscription_type']}")
    print()
    pay_url = sub_info["payment_url"]
    has_hash = "#" in pay_url
    print(f"  链接长度约 {len(pay_url)} 字符（{'含' if has_hash else '缺少'} # 片段）；缺少 #fidnand… 会 Stripe 报错。")

    print("  --- Stripe 打不开时先看这里 ---")
    print("  • 必须从 payment_*.json 里复制整段 payment_url，贴到地址栏。")
    print("  • 终端/IDE/聊天里点的超链接常常在 # 处截断 → Something went wrong / page not found。")
    print("  • Checkout 会话会过期（常约 24h），过期同样会 404。")
    print("  • 可加参数 --open：由本脚本调系统浏览器打开完整 URL。")
    print("  • 可加 --fresh-name：保存为 payment_…_YYYYMMDD_HHMMSS.json（不覆盖旧会话）。")

    print("  ---")
    print("  支付链接 (一次性，请保存):")
    print(f"  {pay_url}")
    print("=" * 50)
    print()

    # 保存结果
    safe_email = email.replace("@", "_").replace("/", "_")[:80]
    stem = f"payment_{account_idx}_{safe_email}"
    if "--fresh-name" in sys.argv[1:]:
        stem += f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    out_file = Path(__file__).parent / f"{stem}.json"
    out_file.write_text(json.dumps({
        "account_index": account_idx,
        "email": email,
        "checkout_source": sub_info.get("source", ""),
        "profile_arn_suffix": profile_arn[-32:],
        "payment_url": sub_info["payment_url"],
        "subscription_type": sub_info["subscription_type"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"结果已保存: {out_file}", "ok")

    if open_stripe:
        log("使用默认浏览器打开完整 Stripe 结账 URL…", "info")
        try:
            webbrowser.open(pay_url)
        except Exception as e:
            log(f"浏览器打开失败: {e}", "warn")

    if cdk:
        cap_cfg = captcha_config_for_stripe_pay()
        if cap_cfg.get("yescaptcha_key"):
            log("已加载 YESCAPTCHA_API_KEY，支付时可用 YesCaptcha 过 hCaptcha", "ok")
        else:
            log("未设置 YESCAPTCHA_API_KEY；若 Stripe 弹出 hCaptcha 会求解失败（请设环境变量）", "warn")
        log("检测到 CDK 码，尝试自动支付 (stripe_pay Playwright)...", "info")
        try:
            from stripe_pay import auto_pay
            result = asyncio.run(auto_pay(
                sub_info["payment_url"],
                cdk,
                captcha_config=cap_cfg,
                headless=False,
                log=log,
            ))
            if result and result.get("ok"):
                log("支付成功!", "ok")
            else:
                log(f"支付未完成: {result}", "err")
        except Exception as e:
            log(f"自动支付异常: {e}", "err")
    else:
        print("  只拿链接（已写入 payment_*.json）可用:")
        print("    python quick_subscribe.py <索引>")
        print("    python quick_subscribe.py <索引> --open")
        print("    python quick_subscribe.py <索引> --fresh-name")
        print("  python quick_subscribe.py <索引> <CDK>")
        print("  $env:YESCAPTCHA_API_KEY='…' ; python quick_subscribe.py <CDK>")


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
