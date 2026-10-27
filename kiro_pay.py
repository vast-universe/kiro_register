"""
Kiro Pro 纯协议支付脚本 — 完全基于 kiro-0.har 实现

用法:
    python3 kiro_pay.py --index 1                    # 从 kiro_accounts.txt 读取第 1 个账号
    python3 kiro_pay.py --url "https://checkout..."  # 直接指定 Stripe URL
    python3 kiro_pay.py --card "5236... 04/31 854"   # 指定卡号
    python3 kiro_pay.py --list                       # 列出账号

依赖: pip install requests
"""

import argparse
import json
import os
import random
import re
import sys
import time
import uuid
import requests

# ═══════════════════════════════════════════════
# 配置区 — 修改这里
# ═══════════════════════════════════════════════
CAPTCHA_RUN_KEY = "b8634607-aef4-4be0-b091-121ed0cd5541"   # captcha.run API key
PROXY = "http://ac2c17f0:ea3b9ce4@res33.kookeey.info:28960"  # 代理，格式: http://user:pass@host:port
# ═══════════════════════════════════════════════

# 从 proxies.txt 随机选代理（如果文件存在）
_PROXIES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt")
if os.path.exists(_PROXIES_FILE):
    import random as _random
    _lines = [l.strip() for l in open(_PROXIES_FILE) if l.strip()]
    if _lines:
        _p = _random.choice(_lines)
        PROXY = f"http://{_p}" if not _p.startswith("http") else _p

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KIRO_ACCOUNTS_FILE = os.path.join(BASE_DIR, "kiro_accounts.txt")
CARD_FILE = os.path.join(BASE_DIR, "card.txt")

# 复用 team/pay.py 的支付引擎
TEAM_DIR = os.path.join(os.path.dirname(BASE_DIR), "team")
sys.path.insert(0, TEAM_DIR)

import pay as stripe_pay

# ── Kiro publishable key 加入缓存，跳过 Playwright ──
stripe_pay.KNOWN_PUBLISHABLE_KEYS["RoAWWIHUhwdEnrT"] = (
    "pk_live_51RoAWWIHUhwdEnrTCxILzldlmzs7DAazo1j2WHmEJWqZFtb4adkY2bQt6PIk0siL41hihKO"
    "PsDskJx1XJvPDQaJX00aaTmV6D0"
)

# ── Kiro 不支持 beta header，使用基础版本 ──
stripe_pay.STRIPE_VERSION_FULL = stripe_pay.STRIPE_VERSION_BASE

STRIPE_API = stripe_pay.STRIPE_API

# ── Kiro HAR 中不存在的请求，直接跳过 ──
stripe_pay.fetch_elements_session = lambda *a, **kw: {}
stripe_pay.lookup_consumer = lambda *a, **kw: {}

# ── 覆盖 register_fingerprint：修正 b.u/b.v 为 Kiro 的值 ──
_orig_register_fingerprint = stripe_pay.register_fingerprint

def _kiro_register_fingerprint(http):
    # 临时 monkey-patch _build_full 里的 u/v 字段
    # 通过替换模块级常量实现：直接覆盖 pay 模块的 _encode_m6 包装
    # 最简单的方式：调用原函数前后无法 patch 内部闭包，
    # 改为直接重写整个函数，只改 u/v 两个字段
    import os, hashlib, random, time, uuid as _uuid
    import pay as _pay

    guid, muid, sid = _pay._gen_fingerprint()
    fp_id = _uuid.uuid4().hex

    screens = [(1920, 1080, 1), (1536, 864, 1.25), (2560, 1440, 1), (1440, 900, 1)]
    sw, sh, dpr = random.choice(screens)
    vh = sh - random.randint(40, 70)
    cpu = random.choice([4, 8, 12, 16])
    canvas_fp = random.choice(_pay._CANVAS_FPS)
    audio_fp = random.choice(_pay._AUDIO_FPS)

    def _b64url_seg():
        return _pay._b64url_seg()

    def _build_full(v2, inc_ids):
        s1, s2, s3, s4, s5 = (_b64url_seg() for _ in range(5))
        ts_now = int(time.time() * 1000)
        return {
            "v2": v2, "id": fp_id,
            "t": round(random.uniform(3, 120), 1),
            "tag": "$npm_package_version", "src": "js",
            "a": {
                "a": {"v": "true", "t": 0},
                "b": {"v": "true", "t": 0},
                "c": {"v": "en-US", "t": 0},
                "d": {"v": "Win32", "t": 0},
                "e": {"v": _pay._PLUGINS_STR, "t": round(random.uniform(0, 0.5), 1)},
                "f": {"v": f"{sw}w_{vh}h_24d_{dpr}r", "t": 0},
                "g": {"v": str(cpu), "t": 0},
                "h": {"v": "false", "t": 0},
                "i": {"v": "sessionStorage-enabled, localStorage-enabled", "t": round(random.uniform(0.5, 2), 1)},
                "j": {"v": canvas_fp, "t": round(random.uniform(5, 120), 1)},
                "k": {"v": "", "t": 0},
                "l": {"v": _pay.USER_AGENT, "t": 0},
                "m": {"v": "", "t": 0},
                "n": {"v": "false", "t": round(random.uniform(3, 50), 1)},
                "o": {"v": audio_fp, "t": round(random.uniform(20, 30), 1)},
            },
            "b": {
                "a": f"https://{s1}.{s2}.{s3}/",
                "b": f"https://checkout.stripe.com/{s4}/{s5}/{_b64url_seg()}",
                "c": _b64url_seg(),
                "d": muid if inc_ids else "NA",
                "e": sid if inc_ids else "NA",
                "f": False, "g": True, "h": True,
                "i": ["location"], "j": [],
                "n": round(random.uniform(800, 2000), 1),
                "u": "checkout.stripe.com", "v": "",   # Kiro: checkout.stripe.com, 无 v
                "w": f"{ts_now}:{hashlib.sha256(os.urandom(32)).hexdigest()}",
            },
            "h": os.urandom(10).hex(),
        }

    def _build_mouse(source):
        return {
            "muid": muid, "sid": sid,
            "url": f"https://{_b64url_seg()}.{_b64url_seg()}/{_b64url_seg()}/{_b64url_seg()}/{_b64url_seg()}",
            "source": source,
            "data": [random.randint(1, 8) for _ in range(10)],
        }

    m6_headers = {
        "User-Agent": _pay.USER_AGENT,
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Origin": "https://m.stripe.network",
        "Referer": "https://m.stripe.network/",
    }
    m6_url = "https://m.stripe.com/6"
    _pay._log("[1/6] 注册浏览器指纹 ...")

    try:
        r1 = http.post(m6_url, data=_pay._encode_m6(_build_full(1, False)), headers=m6_headers, timeout=10)
        if r1.status_code == 200:
            j = r1.json()
            muid = j.get("muid", muid)
            guid = j.get("guid", guid)
            sid = j.get("sid", sid)
            _pay._log("      指纹上报 1/4 完成")
    except Exception as e:
        _pay._log(f"      指纹上报 1/4 失败: {e}")

    try:
        r2 = http.post(m6_url, data=_pay._encode_m6(_build_full(2, True)), headers=m6_headers, timeout=10)
        if r2.status_code == 200:
            j = r2.json()
            guid = j.get("guid", guid)
            _pay._log("      指纹上报 2/4 完成")
    except Exception as e:
        _pay._log(f"      指纹上报 2/4 失败: {e}")

    try:
        http.post(m6_url, data=_pay._encode_m6(_build_mouse("mouse-timings-10-v2")), headers=m6_headers, timeout=10)
        _pay._log("      指纹上报 3/4 完成 (鼠标行为)")
    except Exception:
        pass

    try:
        http.post(m6_url, data=_pay._encode_m6(_build_mouse("mouse-timings-10")), headers=m6_headers, timeout=10)
        _pay._log("      指纹上报 4/4 完成 (鼠标轨迹)")
    except Exception:
        pass

    _pay._log("      浏览器指纹注册完成")
    return guid, muid, sid

stripe_pay.register_fingerprint = _kiro_register_fingerprint


def _checkout_headers():
    """checkout.stripe.com 发出的请求用这个 header（init/pm/confirm/poll）"""
    return {
        "User-Agent": stripe_pay.USER_AGENT,
        "Accept": "application/json",
        "Origin": "https://checkout.stripe.com",
        "Referer": "https://checkout.stripe.com/",
    }


# ── HAR step 2: check_active_subscriptions ──
def _check_active_subscriptions(session, session_id, pk):
    url = (f"{STRIPE_API}/v1/payment_pages/check_active_subscriptions"
           f"?payment_page={session_id}&key={pk}")
    stripe_pay._log("      [2a] check_active_subscriptions...")
    try:
        resp = session.get(url, headers=_checkout_headers())
        stripe_pay._log_response(resp, tag="[2a] check_active_subscriptions")
    except Exception as e:
        stripe_pay._log(f"      [2a] check_active_subscriptions error (ignored): {e}")


# ── HAR step 3 & 5: tax_region 两步更新 ──
def _update_tax_region(session, session_id, pk, addr):
    base_url = f"{STRIPE_API}/v1/payment_pages/{session_id}"
    hdrs = _checkout_headers()

    data1 = {"eid": "NA", "tax_region[country]": addr.get("country", "US"), "key": pk}
    stripe_pay._log("      [3] tax_region country-only update...")
    stripe_pay._log_request("POST", base_url, data=data1, tag="[3] tax_region_country")
    try:
        r = session.post(base_url, data=data1, headers=hdrs)
        stripe_pay._log_response(r, tag="[3] tax_region_country")
    except Exception as e:
        stripe_pay._log(f"      [3] tax_region country error (ignored): {e}")

    data2 = {
        "eid": "NA",
        "tax_region[country]": addr.get("country", "US"),
        "tax_region[state]": addr.get("state", ""),
        "tax_region[city]": addr.get("city", ""),
        "tax_region[postal_code]": addr.get("postal_code", ""),
        "tax_region[line1]": addr.get("line1", ""),
        "key": pk,
    }
    stripe_pay._log("      [5] tax_region full address update...")
    stripe_pay._log_request("POST", base_url, data=data2, tag="[5] tax_region_full")
    try:
        r = session.post(base_url, data=data2, headers=hdrs)
        stripe_pay._log_response(r, tag="[5] tax_region_full")
    except Exception as e:
        stripe_pay._log(f"      [5] tax_region full error (ignored): {e}")


# ── HAR step 4: card-metadata BIN 查询 ──
def _fetch_card_metadata(session, pk, card_number):
    bin_prefix = card_number[:6]
    url = f"{STRIPE_API}/edge-internal/card-metadata?bin_prefix={bin_prefix}&key={pk}"
    stripe_pay._log(f"      [4] card-metadata BIN={bin_prefix}...")
    try:
        resp = session.get(url, headers=_checkout_headers())
        stripe_pay._log_response(resp, tag="[4] card-metadata")
        return resp.json() if resp.status_code == 200 else {}
    except Exception as e:
        stripe_pay._log(f"      [4] card-metadata error (ignored): {e}")
        return {}


# ── 覆盖 update_payment_page_address：HAR 顺序 card-metadata -> tax_region ──
def _kiro_update_payment_page_address(session, pk, session_id, card, ctx, stripe_ver=None):
    addr = card.get("address", {})
    _fetch_card_metadata(session, pk, card["number"])
    _update_tax_region(session, session_id, pk, addr)

stripe_pay.update_payment_page_address = _kiro_update_payment_page_address


# ── 覆盖 init_checkout：Kiro 参数 + check_active_subscriptions ──
def _kiro_init_checkout(session, session_id, pk, locale_profile=None):
    locale_profile = locale_profile or stripe_pay.LOCALE_PROFILES.get("US")
    import uuid as _uuid
    stripe_js_id = str(_uuid.uuid4())
    url = f"{STRIPE_API}/v1/payment_pages/{session_id}/init"

    data = {
        "browser_locale": locale_profile.get("browser_locale", "en-US"),
        "browser_timezone": locale_profile.get("browser_timezone", "America/Chicago"),
        "redirect_type": "url",
        "eid": "NA",
        "key": pk,
    }
    stripe_pay._log("      [1] 初始化结账会话...")
    stripe_pay._log_request("POST", url, data=data, tag="[1] init")
    resp = session.post(url, data=data, headers=_checkout_headers())
    stripe_pay._log_response(resp, tag="[1] init")
    if resp.status_code != 200:
        raise RuntimeError(f"init 失败 [{resp.status_code}]: {resp.text[:500]}")

    init_data = resp.json()
    _check_active_subscriptions(session, session_id, pk)

    ctx = {"stripe_js_id": stripe_js_id}
    # config_id 从 init 响应提取，供 payment_methods 和 confirm 使用
    config_id = init_data.get("config_id") or init_data.get("checkout_config_id", "")
    if config_id:
        ctx["config_id"] = config_id
    return init_data, stripe_pay.STRIPE_VERSION_BASE, ctx

stripe_pay.init_checkout = _kiro_init_checkout


# ── 覆盖 create_payment_method：严格对齐 HAR ──
def _kiro_create_payment_method(session, pk, card, captcha_token, session_id,
                                stripe_ver=None, ctx=None):
    ctx = ctx or {}
    import uuid as _uuid
    addr = card.get("address", {})
    config_id = ctx.get("config_id", "")
    client_session_id = ctx.get("stripe_js_id") or str(_uuid.uuid4())

    data = {
        "type": "card",
        "card[number]": card["number"],
        "card[cvc]": card["cvc"],
        "card[exp_year]": card["exp_year"],
        "card[exp_month]": card["exp_month"],
        "billing_details[name]": card.get("name", ""),
        "billing_details[email]": card.get("email", ""),
        "billing_details[address][country]": addr.get("country", "US"),
        "billing_details[address][line1]": addr.get("line1", ""),
        "billing_details[address][city]": addr.get("city", ""),
        "billing_details[address][postal_code]": addr.get("postal_code", ""),
        "billing_details[address][state]": addr.get("state", ""),
        "payment_user_agent": "stripe.js/c891fde8fc; stripe-js-v3/c891fde8fc; checkout",
        "client_attribution_metadata[client_session_id]": client_session_id,
        "client_attribution_metadata[checkout_session_id]": session_id,
        "client_attribution_metadata[merchant_integration_source]": "checkout",
        "client_attribution_metadata[merchant_integration_version]": "hosted_checkout",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "key": pk,
    }
    if config_id:
        data["client_attribution_metadata[checkout_config_id]"] = config_id
    # guid/muid/sid 来自 register_fingerprint，存在 ctx 里
    if ctx.get("guid"):
        data["guid"] = ctx["guid"]
    if ctx.get("muid"):
        data["muid"] = ctx["muid"]
    if ctx.get("sid"):
        data["sid"] = ctx["sid"]

    url = f"{STRIPE_API}/v1/payment_methods"
    stripe_pay._log("[6/9] 创建支付方式...")
    stripe_pay._log_request("POST", url, data=data, tag="[6/9] create_payment_method")
    resp = session.post(url, data=data, headers=_checkout_headers())
    stripe_pay._log_response(resp, tag="[6/9] create_payment_method")
    if resp.status_code != 200:
        raise RuntimeError(f"创建 payment_method 失败 [{resp.status_code}]: {resp.text[:500]}")
    pm = resp.json()
    pm_id = pm["id"]
    brand = pm.get("card", {}).get("display_brand", "unknown")
    last4 = pm.get("card", {}).get("last4", "????")
    stripe_pay._log(f"      支付方式创建成功: {brand} ****{last4}")
    return pm_id

stripe_pay.create_payment_method = _kiro_create_payment_method


# ── PerimeterX token 获取（HAR 里 confirm 需要 px3/pxvid/pxcts）──
def _fetch_px_tokens(session, locale_profile=None):
    """
    调用 PerimeterX collector API 获取 px3/pxvid/pxcts token。
    这些 token 是 Stripe hosted checkout 的反欺诈验证字段。
    Origin: b.stripecdn.com（Stripe 的 PX 集成页面）
    App ID: PXVl48pWoc（Stripe 的 PX app）
    """
    import uuid as _uuid, hashlib, os as _os, time as _time

    locale_profile = locale_profile or stripe_pay.LOCALE_PROFILES.get("US")
    px_headers = {
        "User-Agent": stripe_pay.USER_AGENT,
        "Accept": "*/*",
        "Origin": "https://b.stripecdn.com",
        "Referer": "https://b.stripecdn.com/",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    # step 1: GET tzm.px-cloud.net/ns 获取 PX session UUID
    px_session_id = str(_uuid.uuid1())
    try:
        r = session.get(
            f"https://tzm.px-cloud.net/ns?c={px_session_id}",
            headers={**px_headers, "Content-Type": "application/json"},
            timeout=10,
        )
        stripe_pay._log(f"      [PX] tzm ns: {r.status_code}")
    except Exception as e:
        stripe_pay._log(f"      [PX] tzm ns error (ignored): {e}")

    # step 2: POST collector（第一次，轻量指纹）
    ts_now = int(_time.time() * 1000)
    pxvid = str(_uuid.uuid1())

    # 构造 collector payload（XOR 0x32 加密的 JSON）
    payload_data = json.dumps([{
        "t": "XiZpJBtLYBM=",
        "d": {
            "MVUGV3c+AmA=": f"https://b.stripecdn.com/stripethirdparty-srv/assets/v32.14/HumanSecurity.html?id={px_session_id}&origin=https%3A%2F%2Fjs.stripe.com",
            "W0MsQR4sLHQ=": 1,
            "XQEqAxhoLzk=": locale_profile.get("platform", "Win32"),
            "dy9AbTFLQF0=": 0,
            "EFQnFlY8ISQ=": random.randint(1800, 2500),
            "Jx8QHWJwFCc=": 3600,
            "GwNsAV1tZDY=": ts_now - random.randint(500, 2000),
            "YQVWByRqXjU=": ts_now - random.randint(100, 500),
            "O2MMIX0KBRU=": px_session_id,
            "UTUmdxRdIEE=": None,
            "EFQnFlU8ISE=": 0,
            "UTUmdxdbIUw=": False,
        }
    }], separators=(',', ':'))

    encrypted = bytes([b ^ 0x32 for b in payload_data.encode()])
    import base64 as _b64
    payload_b64 = _b64.b64encode(encrypted).decode()

    try:
        r1 = session.post(
            "https://collector-pxvl48pwoc.px-cloud.net/api/v2/collector",
            data=f"payload={payload_b64}",
            headers=px_headers,
            timeout=15,
        )
        stripe_pay._log(f"      [PX] collector 1: {r1.status_code}")
    except Exception as e:
        stripe_pay._log(f"      [PX] collector 1 error (ignored): {e}")

    # step 3: HEAD client.px-cloud.net/PXVl48pWoc/main.min.js
    try:
        session.head(
            "https://client.px-cloud.net/PXVl48pWoc/main.min.js",
            headers={**px_headers, "Content-Type": "application/json"},
            timeout=10,
        )
    except Exception:
        pass

    # step 4: POST collector（第二次，完整指纹）
    # 生成 px3 token（格式: sha256_hash:base64_token:1000:base64_data）
    px_hash = hashlib.sha256(_os.urandom(32)).hexdigest()
    px_token = _b64.b64encode(_os.urandom(66)).decode().rstrip('=')[:88]
    px_data = _b64.b64encode(_os.urandom(432)).decode().rstrip('=')[:576]
    px3 = f"{px_hash}:{px_token}:{1000}:{px_data}"

    # 生成 pxcts（格式: base64_32bytes:base64_192chars）
    pxcts_key = _b64.b64encode(_os.urandom(33)).decode().rstrip('=')[:44]
    pxcts_data = _b64.b64encode(_os.urandom(144)).decode().rstrip('=')[:192]
    pxcts = f"{pxcts_key}:{pxcts_data}"

    try:
        r2 = session.post(
            "https://collector-pxvl48pwoc.px-cloud.net/api/v2/collector",
            data=f"payload={payload_b64}",
            headers=px_headers,
            timeout=15,
        )
        stripe_pay._log(f"      [PX] collector 2: {r2.status_code}")
        # 尝试从响应里提取真实的 px3/pxvid
        if r2.status_code == 200 and r2.text:
            try:
                resp_data = r2.json()
                if resp_data.get('px3'):
                    px3 = resp_data['px3']
                if resp_data.get('pxvid'):
                    pxvid = resp_data['pxvid']
                if resp_data.get('pxcts'):
                    pxcts = resp_data['pxcts']
                stripe_pay._log("      [PX] 获取到真实 PX token")
            except Exception:
                pass
    except Exception as e:
        stripe_pay._log(f"      [PX] collector 2 error (ignored): {e}")

    return {"px3": px3, "pxvid": pxvid, "pxcts": pxcts}


# ── 生成 rv_timestamp（Stripe Radar 行为时间序列）──
def _gen_rv_timestamp(locale_profile=None):
    """
    生成 Stripe Radar rv_timestamp 字段。
    格式: 'qto' + base89编码的时间戳序列（字符范围 35-123）
    """
    import time as _time
    locale_profile = locale_profile or stripe_pay.LOCALE_PROFILES.get("US")

    ts_now = int(_time.time() * 1000)
    # 生成一系列时间戳（模拟用户交互时间序列，HAR 里约 52 组）
    timestamps = []
    t = ts_now - random.randint(30000, 60000)  # 页面加载时间
    for _ in range(52):
        t += random.randint(200, 2000)
        timestamps.append(t)

    # base89 编码（字符范围 35-123），每个时间戳编 4 个字符，共 52*4+3=211 -> 加 1 个填充
    def encode_val(v, n=4):
        chars = []
        for _ in range(n):
            chars.append(chr((v % 89) + 35))
            v //= 89
        return ''.join(reversed(chars))

    encoded = 'qto' + ''.join(encode_val(ts % (89**4)) for ts in timestamps)
    # 补齐到 212 字符
    while len(encoded) < 212:
        encoded += chr(random.randint(35, 123))
    return encoded[:212]


# ── 生成 js_checksum（和 pm_id 相关的 Stripe JS 校验）──
def _gen_js_checksum(pm_id):
    """
    生成 Stripe js_checksum 字段。
    格式: 'qto' + base89编码数据
    基于 pm_id 生成，两次 confirm 的差异对应 pm_id 的差异。
    """
    import hashlib
    # 用 pm_id 的哈希生成 checksum
    h = hashlib.sha256(pm_id.encode()).digest()
    # base89 编码
    def encode_bytes(data, n=51):
        result = []
        for i in range(0, min(len(data), n)):
            result.append(chr((data[i] % 89) + 35))
        return ''.join(result)

    return 'qto' + encode_bytes(h * 3)  # 重复以达到足够长度


# ── 覆盖 confirm_payment：严格对齐 HAR（含 PX token）──
def _kiro_confirm_payment(session, pk, session_id, pm_id, captcha_token, init_resp,
                          stripe_ver=None, captcha_cfg=None, captcha_ekey="",
                          ctx=None, locale_profile=None):
    ctx = ctx or {}
    locale_profile = locale_profile or stripe_pay.LOCALE_PROFILES.get("US")
    import uuid as _uuid

    init_checksum = init_resp.get("init_checksum", "")
    config_id = ctx.get("config_id") or init_resp.get("config_id", "")
    client_session_id = ctx.get("stripe_js_id") or str(_uuid.uuid4())

    # 获取 PX token（会话级别，首次获取后缓存到 ctx）
    if not ctx.get("_px_tokens"):
        stripe_pay._log("      [PX] 获取 PerimeterX token...")
        ctx["_px_tokens"] = _fetch_px_tokens(session, locale_profile)
    px = ctx["_px_tokens"]

    data = {
        "eid": "NA",
        "payment_method": pm_id,
        "expected_amount": "0",
        "expected_payment_method_type": "card",
        "key": pk,
        "version": "c891fde8fc",
        "init_checksum": init_checksum,
        "client_attribution_metadata[client_session_id]": client_session_id,
        "client_attribution_metadata[checkout_session_id]": session_id,
        "client_attribution_metadata[merchant_integration_source]": "checkout",
        "client_attribution_metadata[merchant_integration_version]": "hosted_checkout",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        # PerimeterX 反欺诈字段
        "px3": px.get("px3", ""),
        "pxvid": px.get("pxvid", ""),
        "pxcts": px.get("pxcts", ""),
        # Stripe Radar 字段
        "rv_timestamp": _gen_rv_timestamp(locale_profile),
        "js_checksum": _gen_js_checksum(pm_id),
    }
    if config_id:
        data["client_attribution_metadata[checkout_config_id]"] = config_id
    if captcha_token:
        data["passive_captcha_token"] = captcha_token
    # guid/muid/sid 来自 register_fingerprint
    if ctx.get("guid"):
        data["guid"] = ctx["guid"]
    if ctx.get("muid"):
        data["muid"] = ctx["muid"]
    if ctx.get("sid"):
        data["sid"] = ctx["sid"]

    url = f"{STRIPE_API}/v1/payment_pages/{session_id}/confirm"
    stripe_pay._log("[7/9] 确认支付...")
    stripe_pay._log_request("POST", url, data=data, tag="[7/9] confirm")
    resp = session.post(url, data=data, headers=_checkout_headers())
    stripe_pay._log_response(resp, tag="[7/9] confirm")
    if resp.status_code != 200:
        raise RuntimeError(f"confirm 失败 [{resp.status_code}]: {resp.text[:500]}")

    confirm_data = resp.json()
    next_action = confirm_data.get("next_action")
    if not next_action:
        seti = stripe_pay._find_setup_intent(confirm_data)
        if seti and seti.get("next_action"):
            next_action = seti["next_action"]

    if next_action and next_action.get("type") == "use_stripe_sdk":
        stripe_pay._log("      银行要求 3DS 安全验证, 正在处理 ...")

        # 覆盖 verify_challenge 的判断：requires_payment_method = 卡被拒，不是 captcha 问题
        _orig_handle_3ds = stripe_pay._handle_3ds
        import json as _json, re as _re

        def _kiro_handle_3ds(session, pk, confirm_data, captcha_token, stripe_ver,
                             captcha_cfg=None, locale_profile=None, ctx=None):
            # 临时 patch verify_challenge 响应判断
            import pay as _pay
            _orig_post = session.post

            def _patched_post(url, *args, **kwargs):
                # 注入 frontend_execution 到 3ds2/authenticate（HAR 中存在，pay.py 缺失）
                if '3ds2/authenticate' in url:
                    ts_now = int(time.time() * 1000)
                    # fingerprintStartedAt 在约 10 秒前，fingerprintCompletedAt 在 fingerprintStartedAt + 10s
                    # 但两者都必须 <= ts_now
                    fp_started = ts_now - random.randint(10500, 12000)
                    fp_completed = fp_started + 10000  # 固定 10 秒超时
                    fe = json.dumps({
                        "fingerprintOutcome": "timed_out",
                        "fingerprintCompletedAt": fp_completed,
                        "fingerprintTimeout": 10,
                        "fingerprintStartedAt": fp_started,
                    }, separators=(',', ':'))
                    import base64 as _b64
                    fe_encoded = _b64.b64encode(fe.encode()).decode()
                    # 注入到 data 参数
                    if 'data' in kwargs:
                        kwargs['data']['frontend_execution'] = fe_encoded
                    elif args and isinstance(args[0], dict):
                        args[0]['frontend_execution'] = fe_encoded

                # verify_challenge: 去掉 HAR 里不存在的 _stripe_version 字段
                if 'verify_challenge' in url:
                    if 'data' in kwargs and isinstance(kwargs['data'], dict):
                        kwargs['data'].pop('_stripe_version', None)
                    elif args and isinstance(args[0], dict):
                        args[0].pop('_stripe_version', None)

                # 3ds2/authenticate: 同样去掉 _stripe_version
                if '3ds2/authenticate' in url:
                    if 'data' in kwargs and isinstance(kwargs['data'], dict):
                        kwargs['data'].pop('_stripe_version', None)
                    elif args and isinstance(args[0], dict):
                        args[0].pop('_stripe_version', None)

                # 对 Stripe API 请求加重试，应对代理不稳定
                last_exc = None
                for attempt in range(3):
                    try:
                        resp = _orig_post(url, *args, **kwargs)
                        if 'verify_challenge' in url and resp.status_code == 200:
                            try:
                                rdata = resp.json()
                                status = rdata.get('status', '')
                                if status == 'requires_payment_method':
                                    raise RuntimeError(f"卡被拒绝 (requires_payment_method)，请更换卡片")
                            except RuntimeError:
                                raise
                            except Exception:
                                pass
                        return resp
                    except RuntimeError:
                        raise
                    except Exception as e:
                        last_exc = e
                        if attempt < 2:
                            stripe_pay._log(f"      请求失败，重试 ({attempt + 2}/3): {e}")
                            time.sleep(3)
                raise last_exc if last_exc else RuntimeError("请求失败（未知错误）")

            session.post = _patched_post
            try:
                return _orig_handle_3ds(session, pk, confirm_data, captcha_token, stripe_ver,
                                        captcha_cfg=captcha_cfg, locale_profile=locale_profile, ctx=ctx)
            finally:
                session.post = _orig_post

        _kiro_handle_3ds(session, pk, confirm_data, captcha_token,
                         stripe_pay.STRIPE_VERSION_BASE, captcha_cfg,
                         locale_profile=locale_profile, ctx=ctx)

    return confirm_data

stripe_pay.confirm_payment = _kiro_confirm_payment


# ── 覆盖 solve_hcaptcha：使用 captcha.run HCaptcha 任务 ──
def _solve_hcaptcha_captcha_run(captcha_cfg: dict, hcaptcha_config: dict, max_retries: int = 3):
    api_key = captcha_cfg.get("api_key", "")
    if not api_key:
        raise RuntimeError("captcha.run api_key not set (set CAPTCHA_RUN_KEY in kiro_pay.py)")

    site_key = hcaptcha_config.get("site_key", "ec637546-e9b8-447a-ab81-b5fb6d228ab8")
    rqdata = hcaptcha_config.get("rqdata", "")
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}

    for retry in range(max_retries):
        if retry > 0:
            stripe_pay._log(f"      [重试 {retry + 1}/{max_retries}] captcha.run 重新发起")

        if rqdata:
            # 两个 sitekey 都是 hsw PoW 类型，算法相同，只是 s 值不同
            # HCaptchaStripe 文档说只支持 ec637546，但 c7faac4c 算法相同，值得尝试
            payload = {
                "captchaType": "HCaptchaStripe",
                "siteKey": site_key,
                "siteHost": "b.stripecdn.com",
                "rqdata": rqdata,
            }
            stripe_pay._log(f"      captcha.run: HCaptchaStripe siteKey={site_key[:8]}... rqdata=yes")
        else:
            payload = {
                "captchaType": "HCaptcha",
                "siteKey": site_key,
                "siteReferer": "https://b.stripecdn.com/",
                "userAgent": stripe_pay.USER_AGENT,
                "fallbackToActualUA": True,
            }
            stripe_pay._log(f"      captcha.run: HCaptcha siteKey={site_key[:8]}...")

        try:
            resp = requests.post("https://api.captcha-run.com/v2/tasks",
                                 headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
            task_id = resp.json().get("taskId")
            if not task_id:
                stripe_pay._log(f"      captcha.run: no taskId: {resp.json()}")
                time.sleep(3)
                continue
            stripe_pay._log(f"      captcha.run task: {task_id}")
        except Exception as e:
            stripe_pay._log(f"      captcha.run error: {e}")
            time.sleep(3)
            continue

        for attempt in range(60):
            time.sleep(3)
            try:
                r = requests.get(f"https://api.captcha-run.com/v2/tasks/{task_id}",
                                 headers=headers, timeout=15)
                result = r.json()
            except Exception:
                continue
            status = result.get("status", "")
            if status == "Success":
                resp_data = result.get("response", {})
                # HCaptchaStripe 返回 token，HCaptcha 返回 gRecaptchaResponse
                token = resp_data.get("token") or resp_data.get("gRecaptchaResponse", "")
                if token:
                    stripe_pay._log(f"      captcha.run solved: {token[:40]}...")
                    return token, ""
                stripe_pay._log(f"      captcha.run: Success but no token, resp={resp_data}")
                break
            elif status == "Fail":
                stripe_pay._log(f"      captcha.run failed: {result.get('reason', '?')}")
                break
            if attempt % 5 == 4:
                stripe_pay._log(f"      captcha.run waiting... ({attempt + 1}/60)")

    raise RuntimeError(f"captcha.run 解题失败 (已重试 {max_retries} 轮)")

stripe_pay.solve_hcaptcha = _solve_hcaptcha_captcha_run


# ════════════════════════════════════════════════
# 以下为地址生成、账号加载、主流程
# ════════════════════════════════════════════════

# ip-api.com 返回全名，Stripe tax_region 需要州缩写
US_STATE_ABBR = {
    "Alabama": "AL", "Alaska": "AK", "Arizona": "AZ", "Arkansas": "AR",
    "California": "CA", "Colorado": "CO", "Connecticut": "CT", "Delaware": "DE",
    "Florida": "FL", "Georgia": "GA", "Hawaii": "HI", "Idaho": "ID",
    "Illinois": "IL", "Indiana": "IN", "Iowa": "IA", "Kansas": "KS",
    "Kentucky": "KY", "Louisiana": "LA", "Maine": "ME", "Maryland": "MD",
    "Massachusetts": "MA", "Michigan": "MI", "Minnesota": "MN", "Mississippi": "MS",
    "Missouri": "MO", "Montana": "MT", "Nebraska": "NE", "Nevada": "NV",
    "New Hampshire": "NH", "New Jersey": "NJ", "New Mexico": "NM", "New York": "NY",
    "North Carolina": "NC", "North Dakota": "ND", "Ohio": "OH", "Oklahoma": "OK",
    "Oregon": "OR", "Pennsylvania": "PA", "Rhode Island": "RI", "South Carolina": "SC",
    "South Dakota": "SD", "Tennessee": "TN", "Texas": "TX", "Utah": "UT",
    "Vermont": "VT", "Virginia": "VA", "Washington": "WA", "West Virginia": "WV",
    "Wisconsin": "WI", "Wyoming": "WY", "District of Columbia": "DC",
}

US_ADDRESSES = [
    {"country": "US", "state": "CA", "city": "Los Angeles",    "postal_code": "90012"},
    {"country": "US", "state": "NY", "city": "New York",       "postal_code": "10001"},
    {"country": "US", "state": "TX", "city": "Houston",        "postal_code": "77002"},
    {"country": "US", "state": "FL", "city": "Miami",          "postal_code": "33132"},
    {"country": "US", "state": "IL", "city": "Chicago",        "postal_code": "60602"},
    {"country": "US", "state": "WA", "city": "Seattle",        "postal_code": "98104"},
    {"country": "US", "state": "MA", "city": "Boston",         "postal_code": "02110"},
    {"country": "US", "state": "CO", "city": "Denver",         "postal_code": "80202"},
    {"country": "US", "state": "GA", "city": "Atlanta",        "postal_code": "30303"},
    {"country": "US", "state": "PA", "city": "Philadelphia",   "postal_code": "19103"},
    {"country": "US", "state": "AZ", "city": "Phoenix",        "postal_code": "85004"},
    {"country": "US", "state": "OR", "city": "Portland",       "postal_code": "97204"},
    {"country": "US", "state": "NV", "city": "Las Vegas",      "postal_code": "89101"},
    {"country": "US", "state": "TN", "city": "Nashville",      "postal_code": "37203"},
    {"country": "US", "state": "VA", "city": "Arlington",      "postal_code": "22201"},
    {"country": "US", "state": "TX", "city": "Austin",         "postal_code": "78701"},
    {"country": "US", "state": "CA", "city": "San Francisco",  "postal_code": "94102"},
    {"country": "US", "state": "MN", "city": "Minneapolis",    "postal_code": "55401"},
    {"country": "US", "state": "OH", "city": "Columbus",       "postal_code": "43215"},
    {"country": "US", "state": "MI", "city": "Detroit",        "postal_code": "48226"},
]

STREET_NAMES = [
    "Main St", "Oak Ave", "Maple Dr", "Cedar Ln", "Pine St", "Elm St",
    "Washington Blvd", "Park Ave", "Lake Dr", "Hill Rd", "River Rd",
    "Broadway", "Market St", "Spring St", "Highland Ave", "Forest Dr",
]


def get_proxy_location() -> dict:
    """通过代理 IP 查询地理位置"""
    proxies = {"http": PROXY, "https": PROXY} if PROXY else None
    try:
        r = requests.get(
            "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,zip",
            proxies=proxies, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                # ip-api 返回的 regionName 是全名（如 "Massachusetts"），需要转成缩写
                region_name = data.get("regionName", "")
                state_abbr = US_STATE_ABBR.get(region_name, region_name)
                loc = {
                    "country": data.get("countryCode", "US"),
                    "state": state_abbr,
                    "city": data.get("city", ""),
                    "postal_code": data.get("zip", ""),
                }
                print(f"  IP location: {loc['city']}, {loc['state']}, {loc['country']} {loc['postal_code']}")
                return loc
    except Exception as e:
        print(f"  IP lookup failed: {e}")
    return {}


def gen_address(location: dict) -> dict:
    """根据 IP 位置生成账单地址"""
    street = f"{random.randint(100, 9999)} {random.choice(STREET_NAMES)}"
    if location and location.get("city") and location.get("state"):
        return {
            "country": location.get("country", "US"),
            "state": location["state"],
            "city": location["city"],
            "postal_code": location.get("postal_code", ""),
            "line1": street,
        }
    base = random.choice(US_ADDRESSES)
    return {
        "country": base["country"],
        "state": base["state"],
        "city": base["city"],
        "postal_code": base["postal_code"],
        "line1": street,
    }


def load_account(index: int) -> dict:
    with open(KIRO_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
        accounts = json.load(f)
    if index > len(accounts):
        raise ValueError(f"Index {index} out of range (total: {len(accounts)})")
    return accounts[index - 1]


def parse_card(card_str: str) -> dict:
    parts = card_str.strip().split()
    if len(parts) < 3:
        raise ValueError(f"Invalid card format: {card_str}")
    exp = parts[1].split("/")
    return {
        "number": parts[0],
        "exp_month": exp[0],
        "exp_year": exp[1] if len(exp[1]) == 4 else "20" + exp[1],
        "cvc": parts[2],
    }


def load_card_from_file() -> dict:
    if not os.path.exists(CARD_FILE):
        return None
    with open(CARD_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not lines:
        return None
    counter_file = CARD_FILE + ".idx"
    idx = 0
    if os.path.exists(counter_file):
        try:
            idx = int(open(counter_file).read().strip()) % len(lines)
        except Exception:
            idx = 0
    with open(counter_file, "w") as f:
        f.write(str(idx + 1))
    return parse_card(lines[idx])


def build_pay_config(card: dict, location: dict) -> dict:
    addr = gen_address(location)
    locale = location.get("country", "US") if location else "US"
    cfg = {
        "cards": [{
            "number": card["number"],
            "cvc": card["cvc"],
            "exp_month": card["exp_month"],
            "exp_year": card["exp_year"],
            "address": addr,
        }],
        "captcha": {
            "api_url": "https://api.captcha-run.com",
            "api_key": CAPTCHA_RUN_KEY,
        },
        "locale": locale,
    }
    if PROXY:
        m = re.match(r"(?:https?://)?(?:([^:]+):([^@]+)@)?([^:]+):(\d+)", PROXY)
        if m:
            cfg["proxy"] = {
                "host": m.group(3), "port": m.group(4),
                "user": m.group(1) or "", "pass": m.group(2) or "",
            }
    return cfg


def enable_overage(access_token: str) -> bool:
    url = "https://q.us-east-1.amazonaws.com/setUserPreference"
    headers = {
        "content-type": "application/json",
        "user-agent": "aws-sdk-js/1.0.0 ua/2.1 os/darwin lang/js",
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1; max=3",
        "Authorization": f"Bearer {access_token}",
    }
    body = {
        "overageConfiguration": {"overageStatus": "ENABLED"},
        "profileArn": "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX",
    }
    try:
        r = requests.post(url, headers=headers, json=body, timeout=30)
        return r.status_code == 200
    except Exception as e:
        print(f"  Overage error: {e}")
        return False


def import_to_manager(acc_data: dict):
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(BASE_DIR), "any-auto-register"))
        from platforms.kiro.account_manager_upload import upload_to_kiro_manager

        class _Acc:
            def __init__(self, d):
                self.email = d.get("email", "")
                self.password = d.get("password", "")
                self.user_id = ""
                self.token = d.get("accessToken", "")
                self.extra = {
                    "accessToken": d.get("accessToken", ""),
                    "refreshToken": d.get("refreshToken", ""),
                    "clientId": d.get("clientId", ""),
                    "clientSecret": d.get("clientSecret", ""),
                    "provider": "BuilderId",
                    "authMethod": "IdC",
                    "region": "us-east-1",
                }

        ok, msg = upload_to_kiro_manager(_Acc(acc_data))
        print(f"{'✅' if ok else '⚠️'} {msg}")
    except Exception as e:
        print(f"⚠️ 入库失败: {e}")


def main():
    parser = argparse.ArgumentParser(description="Kiro Pro 纯协议支付")
    parser.add_argument("--index", type=int, help="账号序号（1-based）")
    parser.add_argument("--url", type=str, help="Stripe Checkout URL")
    parser.add_argument("--card", type=str, help="卡号 格式: '卡号 月/年 CVV'")
    parser.add_argument("--list", action="store_true", help="列出账号")
    parser.add_argument("--no-overage", action="store_true", help="不开启超额")
    parser.add_argument("--no-import", action="store_true", help="不入库")
    args = parser.parse_args()

    if args.list:
        with open(KIRO_ACCOUNTS_FILE) as f:
            accounts = json.load(f)
        for i, acc in enumerate(accounts):
            flag = "🔗" if acc.get("stripeUrl") else "  "
            print(f"  {i+1}. {flag} {acc.get('email')} [{acc.get('createdAt', '')}]")
        return

    stripe_url = args.url
    acc_data = {}
    access_token = ""

    if args.index:
        acc_data = load_account(args.index)
        stripe_url = stripe_url or acc_data.get("stripeUrl", "")
        access_token = acc_data.get("accessToken", "")
        print(f"Account: {acc_data.get('email')}")

    if not stripe_url:
        print("ERROR: No Stripe URL. Use --url or --index (account must have stripeUrl).")
        sys.exit(1)

    print(f"Stripe URL: {stripe_url[:80]}...")

    card = parse_card(args.card) if args.card else load_card_from_file()
    if not card:
        print("ERROR: No card. Use --card or ensure card.txt exists.")
        sys.exit(1)
    print(f"Card: ****{card['number'][-4:]} {card['exp_month']}/{card['exp_year'][-2:]}")

    if not CAPTCHA_RUN_KEY:
        print("WARNING: CAPTCHA_RUN_KEY not set — hCaptcha may fail")

    print("Querying IP location...")
    location = get_proxy_location()

    pay_cfg = build_pay_config(card, location)
    addr = pay_cfg["cards"][0]["address"]
    print(f"Address: {addr['line1']}, {addr['city']}, {addr['state']} {addr['postal_code']} ({addr['country']})")
    print(f"Locale: {pay_cfg['locale']}")

    tmp_cfg = os.path.join(BASE_DIR, f"_pay_tmp_{int(time.time())}.json")
    with open(tmp_cfg, "w", encoding="utf-8") as f:
        json.dump(pay_cfg, f, ensure_ascii=False)

    print()
    print("=" * 50)
    print("Starting Stripe payment...")
    print("=" * 50)

    try:
        result = stripe_pay.run(stripe_url, card_index=0, config_path=tmp_cfg)
        state = result.get("state", "unknown")
        print()
        if state == "succeeded":
            print("✅ Payment succeeded!")
            if not args.no_overage and access_token:
                print("\n⏳ 开启 Overage...")
                if enable_overage(access_token):
                    print("✅ Overage 已开启！")
                else:
                    print("⚠️ Overage 开启失败")
            if not args.no_import and acc_data:
                print("\n⏳ 导入到 Kiro Account Manager...")
                import_to_manager(acc_data)
        else:
            msgs = {"failed": "❌ Payment failed", "expired": "❌ Session expired", "canceled": "❌ Canceled"}
            print(msgs.get(state, f"❌ state={state}"))
            print(f"  Log: {stripe_pay.LOG_FILE}")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print(f"  Log: {stripe_pay.LOG_FILE}")
    finally:
        try:
            os.remove(tmp_cfg)
        except Exception:
            pass


if __name__ == "__main__":
    main()
