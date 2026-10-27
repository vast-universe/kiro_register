"""
Kiro (AWS Builder ID) 自动注册工具 — iCloud + LuckMail 版

流程分两阶段：
  阶段 1: 并发批量注册（获取邮箱 → 注册 → 获取 Stripe 链接）
  阶段 2: 注册全部完成后，统一执行自动支付

支持两种接码方式：
  1. iCloud: 通过 api798.com HTTP API 获取验证码
  2. LuckMail: 通过 LuckMail 平台 API 获取验证码

用法:
    # 注册
    python main.py                          # 按 config.json 配置运行（只注册）
    python main.py --batch 5 -j 3          # 并发 3 注册 5 个账号
    python main.py --batch 5 -j 3 --pay   # 注册完后自动支付
    python main.py --mode luckmail         # 覆盖接码模式
    python main.py --manual                # 手动输入验证码

    # 支付
    python main.py --pay-only                      # 支付所有未付款账号（顺序）
    python main.py --pay-only --pay-concurrency 2  # 并发 2 个浏览器支付
    python main.py --pay-only 3                    # 只支付第 3 个账号

    # 开启超额
    python main.py --overage               # 为所有已支付账号开启超额

    # 账号管理
    python main.py --list                  # 列出已注册账号
    python main.py --switch                # 切换账号到 Kiro IDE

    # 清理（独立脚本）
    python cleanup.py                      # 清理已完成账号（paid + overage）
    python cleanup.py --invalid            # 清理缺少支付链接或 refreshToken 的无效账号
    python cleanup.py --all-paid           # 清理所有已支付账号
    python cleanup.py --dry-run            # 只预览，不实际操作
"""

import os
import sys
import json
import time
import random
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import KiroRegister, _gen_random_name
from file_lock import file_lock

# ═══ 路径 ═══
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
KIRO_ACCOUNTS_FILE = os.path.join(BASE_DIR, "kiro_accounts.txt")
PROXIES_FILE = os.path.join(BASE_DIR, "proxies.txt")

# 统计
_stats_lock = threading.Lock()
_stats = {"success": 0, "failed": 0, "total": 0}


# ═══ 配置 ═══
def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


# ═══ 代理管理 ═══
def get_proxy() -> str:
    """从 proxies.txt 轮换获取代理（不删除，循环使用，并发安全）"""
    if not os.path.exists(PROXIES_FILE):
        return None
    with file_lock(PROXIES_FILE):
        with open(PROXIES_FILE, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            return None
        counter_file = PROXIES_FILE + ".idx"
        idx = 0
        if os.path.exists(counter_file):
            try:
                idx = int(open(counter_file).read().strip()) % len(lines)
            except:
                idx = 0
        proxy = lines[idx]
        with open(counter_file, 'w') as f:
            f.write(str(idx + 1))
    if not proxy.startswith(("http://", "https://", "socks5://")):
        proxy = f"http://{proxy}"
    print(f"[PROXY] [{idx+1}/{len(lines)}] {proxy[:60]}...")
    return proxy


# ═══ 账号保存 ═══
def save_account(info: dict):
    """保存注册结果（并发安全）"""
    with file_lock(KIRO_ACCOUNTS_FILE):
        accounts = []
        if os.path.exists(KIRO_ACCOUNTS_FILE):
            try:
                with open(KIRO_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                    accounts = json.load(f)
            except:
                accounts = []
        accounts.append({
            "email": info.get("email", ""),
            "password": info.get("password", ""),
            "accessToken": info.get("accessToken", ""),
            "refreshToken": info.get("refreshToken", ""),
            "clientId": info.get("clientId", ""),
            "clientSecret": info.get("clientSecret", ""),
            "csrfToken": info.get("csrfToken", ""),
            "stripeUrl": info.get("stripeUrl", ""),
            "provider": "BuilderId",
            "createdAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        with open(KIRO_ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(accounts, f, indent=2, ensure_ascii=False)


# ═══ 邮箱服务 ═══
def create_mailbox(mode: str, config: dict, proxy: str):
    """根据模式创建邮箱服务"""
    if mode == "icloud":
        from icloud_mailbox import ICloudMailbox
        icloud_cfg = config.get("icloud", {})
        # 账号文件：config.json 的 icloud.accounts_file（默认 accounts.txt）
        accounts_file = icloud_cfg.get("accounts_file") or "accounts.txt"
        if not os.path.isabs(accounts_file):
            accounts_file = os.path.join(BASE_DIR, accounts_file)
        return ICloudMailbox(
            accounts_file=accounts_file,
            api_url=icloud_cfg.get("api_url") or None,
            auth_code=icloud_cfg.get("auth_code") or None,
            proxy=proxy,
            wait_ms=icloud_cfg.get("wait_ms", 10000),
        )
    elif mode == "luckmail":
        from luckmail_mailbox import LuckMailMailbox
        luck_cfg = config.get("luckmail", {})
        api_key = luck_cfg.get("api_key", "")
        if not api_key:
            print("ERROR: LuckMail api_key not configured")
            return None
        return LuckMailMailbox(
            api_key=api_key,
            base_url=luck_cfg.get("base_url") or None,
            api_secret=luck_cfg.get("api_secret", ""),
            project_code=luck_cfg.get("project_code", "kiro"),
            email_type=luck_cfg.get("email_type") or None,
            domain=luck_cfg.get("domain") or None,
            otp_timeout=luck_cfg.get("otp_timeout", 300),
            otp_interval=luck_cfg.get("otp_interval", 3.0),
            use_hmac=luck_cfg.get("use_hmac", False),
        )
    else:
        print(f"ERROR: Unknown mode '{mode}', use 'icloud' or 'luckmail'")
        return None


# ═══ 注册逻辑 ═══
def register_one(config: dict, mode: str = "icloud", manual: bool = False, tag: str = "REG") -> bool:
    """
    注册单个账号（失败自动重试，邮箱不浪费）
    
    重试策略：
    - 代理失败：换代理重试（最多 3 次）
    - 其他错误（超时、网络、服务端错误）：换代理重试
    - OTP 超时：放回邮箱，返回失败（邮箱可能已被注册流程污染）
    - 注册被拒（邮箱已存在等）：不放回邮箱，返回失败
    """
    kiro_cfg = config.get("kiro", {})
    max_retries = config.get("max_retries", 5)  # 总重试次数（含代理切换）

    mailbox = create_mailbox(mode, config, kiro_cfg.get("proxy", "") or get_proxy())
    if not mailbox:
        return False
    if not mailbox.test_connection():
        return False

    try:
        email_addr = mailbox.get_email()
    except Exception as e:
        print(f"[{tag}] ERROR: Failed to get email: {e}")
        return False

    print(f"[{tag}] Email: {email_addr}")
    name_cfg = kiro_cfg.get("name", "random")
    name = _gen_random_name() if name_cfg == "random" else name_cfg

    for attempt in range(max_retries):
        proxy = kiro_cfg.get("proxy", "") or get_proxy()

        # OTP callback 需要每次重试时重新创建（因为旧验证码快照可能过期）
        otp_callback = None if manual else mailbox.create_otp_callback(timeout=300)

        impersonate = kiro_cfg.get("impersonate", "chrome120")
        reg = KiroRegister(proxy=proxy, tag=tag, impersonate=impersonate)

        try:
            ok, info = reg.register(
                email=email_addr,
                name=name,
                otp_timeout=300,
                otp_callback=otp_callback,
            )
        except TimeoutError as e:
            # OTP 超时 — 邮箱可能还能用，放回去
            print(f"[{tag}] OTP timeout, returning email to pool ({attempt+1}/{max_retries})")
            if hasattr(mailbox, 'return_email'):
                mailbox.return_email(email_addr)
            with _stats_lock:
                _stats["failed"] += 1
            return False
        except Exception as e:
            err_msg = str(e)
            # 可重试的错误：代理、网络、连接
            retryable = any(kw in err_msg for kw in [
                "Proxy", "CONNECT", "curl: (56)", "curl: (28)", "curl: (7)", "curl: (35)",
                "Connection", "Timeout", "timeout", "ETIMEDOUT", "ECONNREFUSED",
                "SSLError", "ConnectionReset", "TLS connect error",
            ])
            if retryable and attempt < max_retries - 1:
                wait = random.randint(3, 8)
                print(f"[{tag}] Retryable error: {err_msg[:80]}")
                print(f"[{tag}] Retrying with new proxy in {wait}s... ({attempt+1}/{max_retries})")
                time.sleep(wait)
                continue
            else:
                # 不可重试的错误，放回邮箱
                print(f"[{tag}] ✗ Unrecoverable error: {err_msg[:100]}")
                if hasattr(mailbox, 'return_email'):
                    mailbox.return_email(email_addr)
                with _stats_lock:
                    _stats["failed"] += 1
                return False

        if ok:
            print(f"[{tag}] ✓ Registration successful: {info['email']}")
            # 获取 Stripe Pro 支付链接
            if info.get("accessToken") and info.get("csrfToken"):
                try:
                    stripe_url = reg.get_stripe_link(info["accessToken"], info["csrfToken"])
                    if stripe_url:
                        info["stripeUrl"] = stripe_url
                        print(f"[{tag}] 🔗 {stripe_url[:80]}...")
                except Exception as e:
                    print(f"[{tag}] Stripe link failed: {e}")
            save_account(info)
            with _stats_lock:
                _stats["success"] += 1
            return True
        else:
            error_msg = info.get('error', '')
            # 判断是否是邮箱已注册（不可恢复，换下一个邮箱继续）
            permanent_errors = ["already registered", "already exists", "email is taken",
                                "account already", "duplicate"]
            is_permanent = any(pe in error_msg.lower() for pe in permanent_errors)

            if is_permanent:
                print(f"[{tag}] ⚠️ Email already registered, switching to next email...")
                # 不放回邮箱，取新邮箱继续
                try:
                    email_addr = mailbox.get_email()
                    print(f"[{tag}] New email: {email_addr}")
                    name = _gen_random_name() if name_cfg == "random" else name_cfg
                    continue
                except Exception as e:
                    print(f"[{tag}] ✗ No more emails available: {e}")
                    with _stats_lock:
                        _stats["failed"] += 1
                    return False
            elif attempt < max_retries - 1:
                wait = random.randint(3, 8)
                print(f"[{tag}] ✗ Failed: {error_msg}, retrying in {wait}s... ({attempt+1}/{max_retries})")
                time.sleep(wait)
                continue
            else:
                # 所有重试用完，放回邮箱
                print(f"[{tag}] ✗ All retries exhausted: {error_msg}")
                if hasattr(mailbox, 'return_email'):
                    mailbox.return_email(email_addr)
                with _stats_lock:
                    _stats["failed"] += 1
                return False

    # 不应该到这里
    if hasattr(mailbox, 'return_email'):
        mailbox.return_email(email_addr)
    with _stats_lock:
        _stats["failed"] += 1
    return False


def register_worker(task_id: int, config: dict, mode: str, manual: bool):
    """并发 worker"""
    tag = f"W{task_id:02d}"
    try:
        return register_one(config, mode=mode, manual=manual, tag=tag)
    except Exception as e:
        print(f"[{tag}] ERROR: {e}")
        with _stats_lock:
            _stats["failed"] += 1
        return False


def register_batch(config: dict, count: int, concurrency: int = 1,
                   delay: int = 5, mode: str = "icloud", manual: bool = False):
    """批量注册（支持并发）"""
    print(f"{'=' * 50}")
    print(f"Batch Registration")
    print(f"  Count: {count}")
    print(f"  Concurrency: {concurrency}")
    print(f"  Mode: {mode}")
    print(f"  Delay: {delay}s")
    print(f"{'=' * 50}")

    _stats["success"] = 0
    _stats["failed"] = 0
    _stats["total"] = count
    start_time = time.time()

    if concurrency <= 1:
        # 串行模式
        for i in range(count):
            print(f"\n{'─' * 40}")
            print(f"[{i+1}/{count}] (✓{_stats['success']} ✗{_stats['failed']})")
            print(f"{'─' * 40}")
            register_one(config, mode=mode, manual=manual, tag=f"REG-{i+1}")
            if i < count - 1 and delay > 0:
                wait = delay + random.randint(0, 3)
                print(f"\nWaiting {wait}s...")
                time.sleep(wait)
    else:
        # 并发模式
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            for i in range(count):
                f = executor.submit(register_worker, i + 1, config, mode, manual)
                futures.append(f)
                # 错开启动时间，避免同时请求
                time.sleep(random.uniform(1, 3))

            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    print(f"Worker error: {e}")

    elapsed = time.time() - start_time
    print(f"\n{'=' * 50}")
    print(f"Done in {elapsed:.1f}s")
    print(f"  ✓ Success: {_stats['success']}")
    print(f"  ✗ Failed: {_stats['failed']}")
    print(f"  Speed: {elapsed/max(count,1):.1f}s/account")
    print(f"{'=' * 50}")


# ═══ 账号管理 ═══
def list_accounts():
    if not os.path.exists(KIRO_ACCOUNTS_FILE):
        print("No accounts found.")
        return
    with open(KIRO_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
        accounts = json.load(f)
    print(f"Total: {len(accounts)} accounts")
    for i, acc in enumerate(accounts):
        has_token = bool(acc.get("accessToken"))
        has_refresh = bool(acc.get("refreshToken"))
        print(f"  {i+1}. {acc['email']}  "
              f"{'[token]' if has_token else ''} "
              f"{'[refresh]' if has_refresh else ''} "
              f"[{acc.get('createdAt', '')}]")


def switch_account():
    from switch import switch_kiro_account, refresh_kiro_token
    if not os.path.exists(KIRO_ACCOUNTS_FILE):
        print("No accounts found.")
        return
    with open(KIRO_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
        accounts = json.load(f)
    if not accounts:
        print("No accounts found.")
        return

    print("Available accounts:")
    for i, acc in enumerate(accounts):
        print(f"  {i+1}. {acc['email']} [{acc.get('createdAt', '')}]")

    choice = input("\nSelect account (or 'q' to quit): ").strip()
    if choice.lower() == 'q':
        return
    try:
        acc = accounts[int(choice) - 1]
    except:
        print("Invalid selection")
        return

    rt = acc.get("refreshToken", "")
    cid = acc.get("clientId", "")
    cs = acc.get("clientSecret", "")
    at = acc.get("accessToken", "")

    if rt and cid and cs:
        print("Refreshing token...")
        ok, result = refresh_kiro_token(rt, cid, cs)
        if ok:
            at = result["accessToken"]
            rt = result.get("refreshToken", rt)
            acc["accessToken"] = at
            acc["refreshToken"] = rt
            print("  Token refreshed")

    if not at:
        print("No access token available")
        return

    ok, msg = switch_kiro_account(access_token=at, refresh_token=rt, client_id=cid, client_secret=cs)
    print(f"  {msg}")


# ═══ 入口 ═══
def main():
    parser = argparse.ArgumentParser(
        description="Kiro Auto Registration — iCloud + LuckMail",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--batch", type=int, metavar="N", help="Batch count (overrides config)")
    parser.add_argument("--concurrency", "-j", type=int, metavar="N", help="Concurrency (overrides config)")
    parser.add_argument("--delay", type=int, metavar="S", help="Delay between tasks in seconds")
    parser.add_argument("--mode", type=str, choices=["icloud", "luckmail"], help="Email mode (overrides config)")
    parser.add_argument("--accounts-file", type=str, metavar="PATH",
                        help="iCloud 账号文件（默认取 config.json 的 icloud.accounts_file）")
    parser.add_argument("--manual", action="store_true", help="Manual OTP input")
    parser.add_argument("--pay", action="store_true", help="After all registrations complete, auto-pay for all unpaid accounts")
    parser.add_argument("--pay-only", type=int, nargs='?', const=0, metavar="INDEX",
                        help="Only do payment (0 or omit = all unpaid, N = specific account)")
    parser.add_argument("--pay-concurrency", type=int, default=1, metavar="N",
                        help="Payment concurrency (default: 1, sequential)")
    parser.add_argument("--overage", action="store_true", help="Enable overage for all paid accounts")
    parser.add_argument("--switch", action="store_true", help="Switch account to Kiro IDE")
    parser.add_argument("--list", action="store_true", help="List registered accounts")
    args = parser.parse_args()

    if args.list:
        list_accounts()
        return
    if args.switch:
        switch_account()
        return
    if args.overage:
        _do_overage()
        return
    if args.pay_only is not None:
        # 只做支付（不注册）
        if args.pay_only > 0:
            _do_payment(args.pay_only)
        else:
            _do_payment_all(concurrency=args.pay_concurrency)
        return

    config = load_config()

    # 账号文件覆盖（命令行 > config.json）
    if args.accounts_file:
        config.setdefault("icloud", {})["accounts_file"] = args.accounts_file

    # 合并配置：命令行参数 > config.json
    mode = args.mode or config.get("mode", "icloud")
    batch = args.batch or config.get("batch", 1)
    concurrency = args.concurrency or config.get("concurrency", 1)
    delay = args.delay if args.delay is not None else config.get("delay", 5)

    # ═══ 阶段 1: 注册 ═══
    print("\n" + "═" * 50)
    print("  阶段 1: 批量注册")
    print("═" * 50)

    if batch > 1 or concurrency > 1:
        register_batch(config, count=batch, concurrency=concurrency,
                       delay=delay, mode=mode, manual=args.manual)
    else:
        register_one(config, mode=mode, manual=args.manual)

    # ═══ 阶段 2: 自动支付（注册全部完成后） ═══
    if args.pay:
        print("\n" + "═" * 50)
        print("  阶段 2: 自动支付（所有未支付账号）")
        print("═" * 50)
        _do_payment_all(concurrency=args.pay_concurrency)


def _do_overage():
    """为所有已支付账号批量开启超额（先刷新 token）"""
    from enable_overage import refresh_and_enable

    if not os.path.exists(KIRO_ACCOUNTS_FILE):
        print("ERROR: No accounts")
        return
    with open(KIRO_ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
        accounts = json.load(f)

    # 筛选已支付但未开超额的账号
    targets = [(i, acc) for i, acc in enumerate(accounts) if acc.get("paid") and not acc.get("overage")]
    if not targets:
        print("No paid accounts need overage enabled.")
        return

    print(f"\n⏳ Enabling overage for {len(targets)} paid account(s)...\n")
    success = 0
    for idx, (acc_idx, acc) in enumerate(targets):
        email = acc.get("email", "unknown")
        print(f"  [{idx+1}] {email}...", end=" ")
        ok, new_token = refresh_and_enable(acc)
        if ok:
            print("✓")
            accounts[acc_idx]["overage"] = True
            if new_token:
                accounts[acc_idx]["accessToken"] = new_token
            success += 1
        else:
            print("✗")

    # 保存状态
    with file_lock(KIRO_ACCOUNTS_FILE):
        with open(KIRO_ACCOUNTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(accounts, f, indent=2, ensure_ascii=False)

    print(f"\nDone: {success}/{len(targets)} enabled")


def _do_payment(index: int):
    """为指定账号执行支付"""
    import asyncio
    from auto_pay import auto_pay, load_card, generate_billing_info, get_proxy_country

    if not os.path.exists(KIRO_ACCOUNTS_FILE):
        print("ERROR: No accounts")
        return
    with open(KIRO_ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
        accounts = json.load(f)
    if index > len(accounts):
        print(f"ERROR: Index {index} out of range (total: {len(accounts)})")
        return
    acc = accounts[index - 1]
    url = acc.get("stripeUrl", "")
    proxy = acc.get("proxy", "")
    access_token = acc.get("accessToken", "")

    if not url:
        print(f"ERROR: Account {acc.get('email')} has no stripeUrl. Run without --pay-only first.")
        return

    print(f"Account: {acc.get('email')}")
    card = load_card()
    country = get_proxy_country(proxy)
    billing = generate_billing_info(country)
    asyncio.run(auto_pay(url, proxy=proxy, card=card, billing=billing, access_token=access_token))


def _do_payment_all(concurrency: int = 1):
    """为所有有 stripeUrl 但未支付的账号执行支付"""
    import asyncio
    from auto_pay import auto_pay, load_card, generate_billing_info, get_proxy_country, rollback_card

    if not os.path.exists(KIRO_ACCOUNTS_FILE):
        print("ERROR: No accounts")
        return
    with open(KIRO_ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
        accounts = json.load(f)

    # 筛选有 stripeUrl 且未标记为已支付的账号
    unpaid = [(i, acc) for i, acc in enumerate(accounts)
              if acc.get("stripeUrl") and not acc.get("paid")]

    if not unpaid:
        print("No unpaid accounts with stripeUrl found.")
        return

    print(f"\n📋 Found {len(unpaid)} unpaid account(s) to process:")
    for i, (idx, acc) in enumerate(unpaid):
        print(f"  {i+1}. {acc.get('email')}")

    print(f"\n⏳ Starting payment (concurrency={concurrency})...\n")

    pay_success = 0
    pay_failed = 0

    async def pay_one(acc_idx: int, acc: dict, task_num: int):
        nonlocal pay_success, pay_failed
        tag = f"PAY-{task_num}"
        url = acc.get("stripeUrl", "")
        proxy = acc.get("proxy", "")
        access_token = acc.get("accessToken", "")
        max_card_retries = 3  # 拒卡最多换 3 张卡重试

        print(f"[{tag}] {acc.get('email')}")

        for card_attempt in range(max_card_retries):
            card = load_card()
            if not card:
                print(f"[{tag}] ✗ No card available")
                pay_failed += 1
                return

            country = get_proxy_country(proxy)
            billing = generate_billing_info(country)

            try:
                ok = await auto_pay(url, proxy=proxy, card=card, billing=billing, access_token=access_token)
                if ok:
                    # 标记为已支付
                    with file_lock(KIRO_ACCOUNTS_FILE):
                        with open(KIRO_ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                            all_accs = json.load(f)
                        all_accs[acc_idx]["paid"] = True
                        all_accs[acc_idx]["paidAt"] = time.strftime("%Y-%m-%d %H:%M:%S")
                        with open(KIRO_ACCOUNTS_FILE, 'w', encoding='utf-8') as f:
                            json.dump(all_accs, f, indent=2, ensure_ascii=False)
                    print(f"[{tag}] ✓ Payment success")
                    pay_success += 1
                    return
                else:
                    # auto_pay 返回 False（拒卡/超时等）
                    # 不 rollback — 被拒的卡不归还名额，下次 load_card 自动拿下一张
                    if card_attempt < max_card_retries - 1:
                        print(f"[{tag}] ⚠️ Payment failed (card declined?), trying next card... ({card_attempt+1}/{max_card_retries})")
                        await asyncio.sleep(2)
                        continue
                    else:
                        print(f"[{tag}] ✗ Payment failed after {max_card_retries} card attempts")
                        pay_failed += 1
                        return
            except Exception as e:
                # 异常退出（手动关闭浏览器 = 拒卡），不 rollback，换下一张卡
                print(f"[{tag}] ✗ Payment error: {e}")
                if card_attempt < max_card_retries - 1:
                    print(f"[{tag}] ⚠️ Trying next card... ({card_attempt+1}/{max_card_retries})")
                    await asyncio.sleep(2)
                    continue
                else:
                    print(f"[{tag}] ✗ Payment failed after {max_card_retries} card attempts")
                    pay_failed += 1
                    return

    async def run_payments():
        # 由于 Playwright 需要逐个打开浏览器（UI 交互），按顺序执行
        # concurrency 控制同时打开的浏览器数量
        if concurrency <= 1:
            for i, (idx, acc) in enumerate(unpaid):
                await pay_one(idx, acc, i + 1)
                if i < len(unpaid) - 1:
                    await asyncio.sleep(3)
        else:
            # 分批并发
            sem = asyncio.Semaphore(concurrency)
            async def limited_pay(idx, acc, num):
                async with sem:
                    await pay_one(idx, acc, num)
            tasks = [limited_pay(idx, acc, i + 1) for i, (idx, acc) in enumerate(unpaid)]
            await asyncio.gather(*tasks)

    asyncio.run(run_payments())

    print(f"\n{'═' * 50}")
    print(f"  Payment Summary")
    print(f"  ✓ Success: {pay_success}")
    print(f"  ✗ Failed: {pay_failed}")
    print(f"  Total: {len(unpaid)}")
    print(f"{'═' * 50}")


if __name__ == "__main__":
    main()
