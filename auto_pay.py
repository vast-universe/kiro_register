"""
Kiro Pro 半自动支付 — Playwright + 代理

流程：
1. 用注册时的代理 IP 打开浏览器
2. 根据代理 IP 国家自动生成账单地址
3. 自动填入信用卡信息
4. 暂停让用户手动完成 hCaptcha + 3DS
5. 检测支付成功后返回

依赖：pip install playwright faker && playwright install chromium

用法:
    # 单个支付
    python auto_pay.py --url "https://checkout..." --proxy "http://user:pass@host:port"
    python auto_pay.py --index 1
    python auto_pay.py --no-card --index 2

    # 批量/并发支付（通过 main.py）
    python main.py --pay-only                      # 支付所有未付款账号（顺序）
    python main.py --pay-only --pay-concurrency 2  # 并发 2 个浏览器支付
    python main.py --pay-only 3                    # 只支付第 3 个账号
    python main.py --batch 5 -j 3 --pay           # 注册 5 个后自动支付
"""

import os
import sys
import json
import re
import time
import random
import argparse
import asyncio
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KIRO_ACCOUNTS_FILE = os.path.join(BASE_DIR, "kiro_accounts.txt")
CARDS_FILE = os.path.join(BASE_DIR, "card.txt")
PROXIES_FILE = os.path.join(BASE_DIR, "proxies.txt")

# 美国各州的真实地址数据（街道地址与城市/州/邮编匹配，确保 Stripe 地址验证通过）
# 每条记录包含完整的真实街道地址
US_ADDRESSES = [
    {"state": "CA", "city": "Los Angeles", "zip": "90012", "street": "200 N Spring St"},
    {"state": "CA", "city": "San Francisco", "zip": "94102", "street": "1 Dr Carlton B Goodlett Pl"},
    {"state": "CA", "city": "San Diego", "zip": "92101", "street": "202 C St"},
    {"state": "CA", "city": "Sacramento", "zip": "95814", "street": "915 I St"},
    {"state": "NY", "city": "New York", "zip": "10007", "street": "1 Centre St"},
    {"state": "NY", "city": "Brooklyn", "zip": "11201", "street": "209 Joralemon St"},
    {"state": "NY", "city": "Buffalo", "zip": "14202", "street": "65 Niagara Sq"},
    {"state": "TX", "city": "Houston", "zip": "77002", "street": "901 Bagby St"},
    {"state": "TX", "city": "Dallas", "zip": "75201", "street": "1500 Marilla St"},
    {"state": "TX", "city": "Austin", "zip": "78701", "street": "301 W 2nd St"},
    {"state": "TX", "city": "San Antonio", "zip": "78205", "street": "100 Military Plaza"},
    {"state": "FL", "city": "Miami", "zip": "33130", "street": "3500 Pan American Dr"},
    {"state": "FL", "city": "Orlando", "zip": "32801", "street": "400 S Orange Ave"},
    {"state": "FL", "city": "Tampa", "zip": "33602", "street": "306 E Jackson St"},
    {"state": "FL", "city": "Jacksonville", "zip": "32202", "street": "117 W Duval St"},
    {"state": "IL", "city": "Chicago", "zip": "60602", "street": "121 N LaSalle St"},
    {"state": "IL", "city": "Springfield", "zip": "62701", "street": "300 S 7th St"},
    {"state": "WA", "city": "Seattle", "zip": "98104", "street": "600 4th Ave"},
    {"state": "WA", "city": "Tacoma", "zip": "98402", "street": "747 Market St"},
    {"state": "MA", "city": "Boston", "zip": "02201", "street": "1 City Hall Sq"},
    {"state": "MA", "city": "Cambridge", "zip": "02139", "street": "795 Massachusetts Ave"},
    {"state": "CO", "city": "Denver", "zip": "80202", "street": "1437 Bannock St"},
    {"state": "CO", "city": "Boulder", "zip": "80302", "street": "1777 Broadway"},
    {"state": "GA", "city": "Atlanta", "zip": "30303", "street": "55 Trinity Ave SW"},
    {"state": "GA", "city": "Savannah", "zip": "31401", "street": "2 E Bay St"},
    {"state": "PA", "city": "Philadelphia", "zip": "19107", "street": "1401 John F Kennedy Blvd"},
    {"state": "PA", "city": "Pittsburgh", "zip": "15219", "street": "414 Grant St"},
    {"state": "AZ", "city": "Phoenix", "zip": "85003", "street": "200 W Washington St"},
    {"state": "AZ", "city": "Tucson", "zip": "85701", "street": "255 W Alameda St"},
    {"state": "OH", "city": "Columbus", "zip": "43215", "street": "90 W Broad St"},
    {"state": "OH", "city": "Cleveland", "zip": "44114", "street": "601 Lakeside Ave"},
    {"state": "NC", "city": "Charlotte", "zip": "28202", "street": "600 E 4th St"},
    {"state": "NC", "city": "Raleigh", "zip": "27601", "street": "222 W Hargett St"},
    {"state": "MI", "city": "Detroit", "zip": "48226", "street": "2 Woodward Ave"},
    {"state": "MI", "city": "Ann Arbor", "zip": "48104", "street": "301 E Huron St"},
    {"state": "NJ", "city": "Newark", "zip": "07102", "street": "920 Broad St"},
    {"state": "NJ", "city": "Jersey City", "zip": "07302", "street": "280 Grove St"},
    {"state": "VA", "city": "Richmond", "zip": "23219", "street": "900 E Broad St"},
    {"state": "VA", "city": "Arlington", "zip": "22201", "street": "2100 Clarendon Blvd"},
    {"state": "OR", "city": "Portland", "zip": "97204", "street": "1221 SW 4th Ave"},
    {"state": "MN", "city": "Minneapolis", "zip": "55415", "street": "350 S 5th St"},
    {"state": "NV", "city": "Las Vegas", "zip": "89101", "street": "495 S Main St"},
    {"state": "TN", "city": "Nashville", "zip": "37201", "street": "1 Public Sq"},
    {"state": "MO", "city": "Kansas City", "zip": "64106", "street": "414 E 12th St"},
    {"state": "MD", "city": "Baltimore", "zip": "21202", "street": "100 N Holliday St"},
    {"state": "WI", "city": "Milwaukee", "zip": "53202", "street": "200 E Wells St"},
    {"state": "IN", "city": "Indianapolis", "zip": "46204", "street": "200 E Washington St"},
    {"state": "CT", "city": "Hartford", "zip": "06103", "street": "550 Main St"},
    {"state": "UT", "city": "Salt Lake City", "zip": "84111", "street": "451 S State St"},
    {"state": "SC", "city": "Charleston", "zip": "29401", "street": "80 Broad St"},
]

# 名字池
FIRST_NAMES = ["James", "Robert", "John", "Michael", "David", "William", "Richard", "Joseph",
               "Thomas", "Christopher", "Charles", "Daniel", "Matthew", "Anthony", "Mark",
               "Mary", "Patricia", "Jennifer", "Linda", "Barbara", "Elizabeth", "Susan", "Jessica",
               "Sarah", "Karen", "Lisa", "Nancy", "Betty", "Margaret", "Sandra"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
              "Rodriguez", "Martinez", "Wilson", "Anderson", "Taylor", "Thomas", "Moore", "Jackson",
              "Martin", "Lee", "Thompson", "White", "Harris", "Clark", "Lewis", "Robinson",
              "Walker", "Young", "Allen", "King", "Wright", "Scott"]


def generate_billing_info(proxy_country: str = "US") -> dict:
    """随机生成美国账单信息（固定 US，不依赖代理 IP）
    
    使用预定义的真实地址（街道+城市+州+邮编完全匹配），避免 Stripe 地址验证失败。
    """
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    name = f"{first} {last}"
    email = f"{first.lower()}{random.randint(10,999)}@gmail.com"

    addr = random.choice(US_ADDRESSES)
    return {
        "name": name,
        "email": email,
        "country": "US",
        "state": addr["state"],
        "city": addr["city"],
        "zip": addr["zip"],
        "street": addr["street"],
    }


def load_card(commit: bool = False) -> dict:
    """
    从 card.txt 轮换加载卡（格式: 卡号 月/年 CVV）— 每张卡成功绑2次后切换下一张
    
    并发安全：整个读取+预占操作在同一个文件锁内完成。
    
    idx 文件格式（JSON，人类可读）:
    {
      "next": 10,
      "cards": {
        "****2201": {"idx": 0, "used": 2},
        "****1288": {"idx": 1, "used": 2},
        "****8073": {"idx": 9, "used": 1}
      }
    }
    
    Args:
        commit: False = 预占一个名额并返回卡信息（支付开始时调用）
                True = 确认支付成功（不做额外操作，因为预占时已计数）
    
    如果支付失败，需要调用 rollback_card(card_idx) 回退指定卡的计数。
    """
    from file_lock import file_lock

    if not os.path.exists(CARDS_FILE):
        return None

    counter_file = CARDS_FILE + ".idx"
    MAX_USES_PER_CARD = 2

    with file_lock(CARDS_FILE):
        with open(CARDS_FILE, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

        if not lines:
            return None

        # 读取状态
        state = _load_card_state(counter_file, lines)

        if commit:
            return None

        # 找到下一张可用的卡（used < MAX）
        total_cards = len(lines)
        start_idx = state["next"]
        found_idx = None

        for offset in range(total_cards):
            check_idx = (start_idx + offset) % total_cards
            card_number = lines[check_idx].split()[0]
            card_key = f"****{card_number[-4:]}"
            used = state["cards"].get(card_key, {}).get("used", 0)
            if used < MAX_USES_PER_CARD:
                found_idx = check_idx
                break

        if found_idx is None:
            print("ERROR: 所有卡都已用满！")
            return None

        # 预占名额
        card_number = lines[found_idx].split()[0]
        card_key = f"****{card_number[-4:]}"
        if card_key not in state["cards"]:
            state["cards"][card_key] = {"idx": found_idx, "used": 0}
        current_used = state["cards"][card_key]["used"]
        state["cards"][card_key]["used"] = current_used + 1

        # 更新 next 指针
        if state["cards"][card_key]["used"] >= MAX_USES_PER_CARD:
            state["next"] = (found_idx + 1) % total_cards
        else:
            state["next"] = found_idx

        _save_card_state(counter_file, state)

    # 锁释放后解析卡信息
    parts = lines[found_idx].split()
    if len(parts) < 3:
        print(f"ERROR: card.txt 第 {found_idx+1} 行格式错误，需要: 卡号 月/年 CVV")
        return None

    number = parts[0]
    exp = parts[1]
    cvc = parts[2]

    exp_parts = exp.split("/")
    exp_month = exp_parts[0]
    exp_year = exp_parts[1] if len(exp_parts[1]) == 4 else "20" + exp_parts[1]

    print(f"  Card [{found_idx+1}/{len(lines)}]: ****{number[-4:]} (slot {current_used+1}/{MAX_USES_PER_CARD})")

    return {
        "number": number,
        "exp_month": exp_month,
        "exp_year": exp_year,
        "cvc": cvc,
        "_card_idx": found_idx,
    }


def rollback_card(card_idx: int):
    """支付失败时回退指定卡的计数（归还预占的名额）"""
    from file_lock import file_lock

    if card_idx is None:
        return

    counter_file = CARDS_FILE + ".idx"
    with file_lock(CARDS_FILE):
        with open(CARDS_FILE, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

        if not lines or card_idx >= len(lines):
            return

        state = _load_card_state(counter_file, lines)
        card_number = lines[card_idx].split()[0]
        card_key = f"****{card_number[-4:]}"

        if card_key in state["cards"]:
            current = state["cards"][card_key]["used"]
            if current > 0:
                state["cards"][card_key]["used"] = current - 1
                # 回退后这张卡有空位，把 next 拉回来
                if card_idx < state["next"]:
                    state["next"] = card_idx
                _save_card_state(counter_file, state)
                print(f"  Card rollback: {card_key} (now {current-1}/2)")


def _load_card_state(counter_file: str, lines: list) -> dict:
    """加载卡状态（兼容旧格式自动迁移）"""
    state = {"next": 0, "cards": {}}

    if not os.path.exists(counter_file):
        return state

    try:
        content = open(counter_file).read().strip()
        if content.startswith('{'):
            loaded = json.loads(content)
            if "cards" in loaded:
                # 新格式，直接用
                state = loaded
            elif "slots" in loaded:
                # 中间格式（带 slots），迁移到 cards
                state["next"] = loaded.get("next", 0)
                for idx_str, count in loaded["slots"].items():
                    idx = int(idx_str)
                    if idx < len(lines):
                        card_number = lines[idx].split()[0]
                        card_key = f"****{card_number[-4:]}"
                        state["cards"][card_key] = {"idx": idx, "used": count}
        elif ':' in content:
            # 最旧格式 "idx:count"
            parts = content.split(':')
            idx = int(parts[0])
            count = int(parts[1])
            if count >= 2:
                state["next"] = idx + 1
            else:
                state["next"] = idx
            if count > 0 and idx < len(lines):
                card_number = lines[idx].split()[0]
                card_key = f"****{card_number[-4:]}"
                state["cards"][card_key] = {"idx": idx, "used": count}
    except:
        pass

    return state


def _save_card_state(counter_file: str, state: dict):
    """保存卡状态为格式化 JSON（方便查看）"""
    with open(counter_file, 'w') as f:
        json.dump(state, f, indent=2)


def get_proxy_country(proxy: str) -> str:
    """固定返回 US（不再根据代理推断）"""
    return "US"


async def auto_pay(url: str, proxy: str = None, card: dict = None,
                   billing: dict = None, access_token: str = None) -> bool:
    """
    半自动支付

    Returns:
        是否支付成功
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("ERROR: pip install playwright && playwright install chromium")
        return False

    print(f"\n{'=' * 50}")
    print(f"💳 Opening Stripe Checkout...")
    print(f"  URL: {url[:80]}...")
    if proxy:
        print(f"  Proxy: {proxy[:60]}...")
    print(f"{'=' * 50}\n")

    # 解析代理为 Playwright 格式
    pw_proxy = None
    if proxy:
        parsed = urlparse(proxy)
        pw_proxy = {
            "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
        }
        if parsed.username:
            pw_proxy["username"] = parsed.username
            pw_proxy["password"] = parsed.password or ""

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            args=['--disable-blink-features=AutomationControlled'],
            proxy=pw_proxy,
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            locale="en-US",
        )
        page = await context.new_page()

        # 打开支付页面
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            print(f"  Page load: {e}")
            # 继续，页面可能部分加载了

        print("✅ 页面已加载")
        await page.wait_for_timeout(5000)  # 等待 Stripe JS 和 iframe 加载

        # 自动填入信息
        if card and billing:
            print("⏳ 自动填入信息...")
            try:
                # Email
                email_input = page.locator('input#email, input[name="email"]')
                if await email_input.count() > 0:
                    await email_input.click()
                    await email_input.fill(billing["email"])
                    print(f"  ✓ Email: {billing['email']}")
                    await page.wait_for_timeout(500)

                # 卡号 — 直接遍历 page.frames 找包含卡号输入的 frame
                await page.wait_for_timeout(5000)  # 等 iframe 加载
                card_filled = False

                for frame in page.frames:
                    try:
                        # 找卡号输入框
                        card_input = frame.locator('input[name="cardnumber"]')
                        if await card_input.count() == 0:
                            card_input = frame.locator('input[autocomplete="cc-number"]')
                        if await card_input.count() == 0:
                            continue

                        await card_input.click()
                        for ch in card["number"]:
                            await card_input.press(ch)
                            await page.wait_for_timeout(random.randint(30, 80))
                        print(f"  ✓ Card: ****{card['number'][-4:]}")
                        card_filled = True

                        # 过期日期
                        await page.wait_for_timeout(500)
                        for exp_sel in ['input[name="exp-date"]', 'input[name="cardExpiry"]', 'input[autocomplete="cc-exp"]', 'input[placeholder*="MM"]']:
                            exp_input = frame.locator(exp_sel)
                            if await exp_input.count() > 0:
                                await exp_input.click()
                                exp_str = f"{card['exp_month']}{card['exp_year'][-2:]}"
                                for ch in exp_str:
                                    await exp_input.press(ch)
                                    await page.wait_for_timeout(random.randint(30, 80))
                                print(f"  ✓ Exp: {card['exp_month']}/{card['exp_year'][-2:]}")
                                break
                        else:
                            # Tab 跳转
                            await card_input.press("Tab")
                            await page.wait_for_timeout(300)
                            for ch in f"{card['exp_month']}{card['exp_year'][-2:]}":
                                await page.keyboard.press(ch)
                                await page.wait_for_timeout(50)
                            print(f"  ✓ Exp (tab): {card['exp_month']}/{card['exp_year'][-2:]}")

                        # CVC
                        await page.wait_for_timeout(500)
                        for cvc_sel in ['input[name="cvc"]', 'input[name="cardCvc"]', 'input[autocomplete="cc-csc"]', 'input[placeholder*="CVC"]', 'input[placeholder*="123"]']:
                            cvc_input = frame.locator(cvc_sel)
                            if await cvc_input.count() > 0:
                                await cvc_input.click()
                                for ch in card["cvc"]:
                                    await cvc_input.press(ch)
                                    await page.wait_for_timeout(random.randint(30, 80))
                                print(f"  ✓ CVC: ***")
                                break
                        else:
                            await page.keyboard.press("Tab")
                            await page.wait_for_timeout(300)
                            for ch in card["cvc"]:
                                await page.keyboard.press(ch)
                                await page.wait_for_timeout(50)
                            print(f"  ✓ CVC (tab): ***")
                        break
                    except Exception as ex:
                        continue

                if not card_filled:
                    print("  ⚠️ 无法自动填入卡号（iframe 未找到），请手动填入")

                await page.wait_for_timeout(1000)

                # 姓名
                name_input = page.locator('input#billingName, input[name="billingName"]')
                if await name_input.count() > 0:
                    await name_input.click()
                    await name_input.fill(billing["name"])
                    print(f"  ✓ Name: {billing['name']}")

                # 国家
                country_select = page.locator('select#billingCountry, select[name="billingCountry"]')
                if await country_select.count() > 0:
                    await country_select.select_option(billing["country"])
                    print(f"  ✓ Country: {billing['country']}")
                    await page.wait_for_timeout(1000)

                # 地址 — 输入后等待 Google Places 下拉出现，出现后再关闭，避免遮挡后续输入框
                addr_input = page.locator('input#billingAddressLine1, input[name="billingAddressLine1"]')
                if await addr_input.count() > 0:
                    await addr_input.click()
                    await addr_input.fill(billing["street"])

                    # 等待下拉出现（最多等 5 秒）
                    dropdown_selectors = [
                        '.pac-container',  # Google Places autocomplete
                        '[role="listbox"]',
                        '.autocomplete-suggestions',
                    ]
                    dropdown_appeared = False
                    for _ in range(25):  # 25 * 200ms = 5s
                        for sel in dropdown_selectors:
                            dd = page.locator(sel)
                            if await dd.count() > 0:
                                try:
                                    if await dd.first.is_visible():
                                        dropdown_appeared = True
                                        break
                                except:
                                    pass
                        if dropdown_appeared:
                            break
                        await page.wait_for_timeout(200)

                    # 下拉出现了，关闭它
                    if dropdown_appeared:
                        await page.keyboard.press("Escape")
                        await page.wait_for_timeout(300)
                        # 确认关闭
                        for sel in dropdown_selectors:
                            dd = page.locator(sel)
                            if await dd.count() > 0:
                                try:
                                    if await dd.first.is_visible():
                                        await page.keyboard.press("Escape")
                                        await page.wait_for_timeout(300)
                                        break
                                except:
                                    pass

                    # 点击姓名框转移焦点，触发地址表单展开
                    name_el = page.locator('input#billingName, input[name="billingName"]')
                    if await name_el.count() > 0:
                        await name_el.click()
                    await page.wait_for_timeout(500)
                    print(f"  ✓ Address: {billing['street']}")

                # 城市
                city_input = page.locator('input#billingLocality, input[name="billingLocality"]')
                if await city_input.count() > 0:
                    await city_input.click()
                    await city_input.fill(billing["city"])
                    await page.wait_for_timeout(300)

                # 邮编
                zip_input = page.locator('input#billingPostalCode, input[name="billingPostalCode"]')
                if await zip_input.count() > 0:
                    await zip_input.click()
                    await zip_input.fill(billing["zip"])

                # 州
                state_input = page.locator('select#billingAdministrativeArea, input#billingAdministrativeArea')
                if await state_input.count() > 0:
                    try:
                        await state_input.select_option(billing["state"])
                    except:
                        await state_input.fill(billing["state"])
                    print(f"  ✓ Address: {billing['street']}, {billing['city']}, {billing['state']} {billing['zip']}")

                print("\n✅ 信息已填入")
                await page.wait_for_timeout(1000)

                # 尝试自动解决 hCaptcha（如果配置了 captcha.run API key）
                captcha_api_key = os.environ.get("CAPTCHA_RUN_KEY", "")
                # 也从 config.json 读取
                if not captcha_api_key:
                    try:
                        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
                        with open(cfg_path) as f:
                            _cfg = __import__('json').load(f)
                        captcha_api_key = _cfg.get("captcha_run_key", "")
                    except:
                        pass
                if captcha_api_key:
                    print(f"  ⏳ 自动解决 hCaptcha (captcha.run)...")
                    try:
                        from solve_captcha import solve_stripe_hcaptcha

                        # 尝试从页面拦截 rqdata（可选，有则用 HCaptchaStripe）
                        rqdata = None
                        rqdata_holder = []
                        async def intercept_hcaptcha(route):
                            req = route.request
                            if "getcaptcha" in req.url and "hcaptcha" in req.url:
                                post_data = req.post_data or ""
                                m = re.search(r'"rqdata"\s*:\s*"([^"]+)"', post_data)
                                if m:
                                    rqdata_holder.append(m.group(1))
                            await route.continue_()
                        await page.route("**/*", intercept_hcaptcha)
                        await page.wait_for_timeout(2000)
                        await page.unroute("**/*", intercept_hcaptcha)
                        rqdata = rqdata_holder[0] if rqdata_holder else None

                        token = solve_stripe_hcaptcha(
                            page_url=url,
                            api_key=captcha_api_key,
                            rqdata=rqdata,
                        )
                        if token:
                            # 注入 token（参考 captcha.run 文档的注入方式）
                            await page.evaluate("""
                                (token) => {
                                    for (const ele of document.querySelectorAll("iframe[data-hcaptcha-widget-id]")) {
                                        const id = ele.attributes["data-hcaptcha-widget-id"].value;
                                        const data = JSON.stringify({
                                            source: "hcaptcha",
                                            label: "challenge-closed",
                                            id,
                                            contents: {
                                                event: "challenge-passed",
                                                response: token,
                                                expiration: 120
                                            }
                                        });
                                        window.dispatchEvent(new MessageEvent('message', {data}));
                                    }
                                }
                            """, token)
                            print(f"  ✅ hCaptcha token injected")
                            await page.wait_for_timeout(1000)
                    except Exception as e:
                        print(f"  ⚠️ hCaptcha auto-solve failed: {e}")

                # 自动点击订阅按钮 — 先等待税率计算完成
                subscribe_btn = page.locator('button[type="submit"], button:has-text("Subscribe"), button:has-text("订阅")')
                if await subscribe_btn.count() > 0:
                    # 等待税率计算完成（Stripe 会显示 spinner/loading，或按钮暂时 disabled）
                    print("  ⏳ 等待税率计算完成...")
                    tax_loading_selectors = [
                        '.LoadingIndicator',           # Stripe loading spinner
                        '[data-testid="loading"]',
                        '.TaxCalculating',
                        'svg.animate-spin',            # 通用 spinner
                        '.spinner',
                    ]
                    for _ in range(30):  # 最多等 15 秒（30 * 500ms）
                        # 检查是否有 loading 指示器
                        is_loading = False
                        for sel in tax_loading_selectors:
                            loader = page.locator(sel)
                            if await loader.count() > 0:
                                try:
                                    if await loader.first.is_visible():
                                        is_loading = True
                                        break
                                except:
                                    pass
                        # 检查按钮是否 disabled（Stripe 计算中会禁用按钮）
                        if not is_loading:
                            btn_disabled = await subscribe_btn.first.is_disabled()
                            if btn_disabled:
                                is_loading = True
                        if not is_loading:
                            break
                        await page.wait_for_timeout(500)

                    # 额外等待一下确保页面稳定（税率数字渲染）
                    await page.wait_for_timeout(1500)

                    # 再次确认按钮可点击
                    try:
                        await subscribe_btn.first.wait_for(state="visible", timeout=5000)
                    except:
                        pass

                    await subscribe_btn.first.click()
                    print("  ✓ 已点击订阅按钮")

            except Exception as e:
                print(f"  ⚠️ 自动填入部分失败: {e}")

        # 等待支付完成（检测页面跳转到 kiro.dev）
        print()
        print("=" * 50)
        print("🖐️  请手动完成：")
        print("  1. 完成 hCaptcha 验证")
        print("  2. 点击 Subscribe / 订阅按钮")
        print("  3. 完成 3DS 银行验证（如果弹出）")
        print("  → 支付成功后页面会自动跳转，脚本会自动继续")
        print("=" * 50)
        print()

        # 自动检测支付成功（页面跳转到 kiro.dev 或出现 success）
        print("⏳ 等待支付完成（检测页面跳转）...")
        payment_success = False
        timeout = 300  # 5 分钟超时
        start = time.time()

        while time.time() - start < timeout:
            current_url = page.url
            if "kiro.dev" in current_url and "checkout.stripe.com" not in current_url:
                payment_success = True
                print(f"✅ 支付成功！页面已跳转到: {current_url[:80]}")
                break
            # 也检查页面内容是否有成功提示
            try:
                for text_hint in ["Payment successful", "Thank you", "Subscription active"]:
                    if await page.locator(f"text={text_hint}").count() > 0:
                        payment_success = True
                        print(f"✅ 检测到支付成功提示: {text_hint}")
                        break
            except:
                pass
            await page.wait_for_timeout(2000)

        if not payment_success:
            print("⚠️ 超时或未检测到支付成功")
            print("  如果已支付成功，按 Enter 继续；输入 'n' 跳过...")
            loop = asyncio.get_event_loop()
            user_input = await loop.run_in_executor(None, input)
            if user_input.strip().lower() != 'n':
                payment_success = True  # 用户确认成功

        await page.wait_for_timeout(3000)
        await browser.close()

    # 支付成功 → 确认卡绑定
    if payment_success:
        load_card(commit=True)
    # 支付失败不 rollback — 被拒的卡不归还名额，由外层决定是否换卡重试

    # 支付完成后入库（overage 暂不自动开启，避免触发安全锁定）
    if payment_success and access_token:
        # print("\n⏳ 开启 Overage...")
        # from enable_overage import enable_overage
        # if enable_overage(access_token):
        #     print("✅ Overage 已开启！")
        # else:
        #     print("⚠️ Overage 开启失败（可能需要等几分钟再试）")
        print("\n💡 Overage 跳过（稍后可手动运行: python enable_overage.py）")

        # 入库到 Kiro Account Manager
        print("\n⏳ 导入到 Kiro Account Manager...")
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "any-auto-register"))
            from platforms.kiro.account_manager_upload import upload_to_kiro_manager

            # 构造 account 对象
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

            # 从 kiro_accounts.txt 读取当前账号完整信息
            acc_data = {}
            if os.path.exists(KIRO_ACCOUNTS_FILE):
                with open(KIRO_ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                    all_accs = json.load(f)
                # 找到 access_token 对应的账号
                for a in all_accs:
                    if a.get("accessToken", "").startswith(access_token[:20]):
                        acc_data = a
                        break

            if acc_data:
                ok, msg = upload_to_kiro_manager(_Acc(acc_data))
                if ok:
                    print(f"✅ {msg}")
                else:
                    print(f"⚠️ {msg}")
            else:
                print("⚠️ 未找到账号信息，跳过入库")
        except Exception as e:
            print(f"⚠️ 入库失败: {e}")

    return payment_success


def main():
    parser = argparse.ArgumentParser(description="Kiro Pro Semi-Auto Payment")
    parser.add_argument("--url", type=str, help="Stripe checkout URL")
    parser.add_argument("--proxy", type=str, help="Proxy URL")
    parser.add_argument("--index", type=int, help="Account index from kiro_accounts.txt")
    parser.add_argument("--no-card", action="store_true", help="Don't auto-fill card")
    args = parser.parse_args()

    # 获取支付链接和 token
    url = args.url
    proxy = args.proxy
    access_token = None

    # 如果没有指定代理，从 proxies.txt 轮换读一个（不删除）
    if not proxy and not args.url:
        if os.path.exists(PROXIES_FILE):
            with open(PROXIES_FILE, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                counter_file = PROXIES_FILE + ".pay.idx"
                idx = 0
                if os.path.exists(counter_file):
                    try:
                        idx = int(open(counter_file).read().strip()) % len(lines)
                    except:
                        idx = 0
                proxy = lines[idx]
                if not proxy.startswith(("http://", "https://", "socks5://")):
                    proxy = f"http://{proxy}"
                with open(counter_file, 'w') as f:
                    f.write(str(idx + 1))
                print(f"[PROXY] [{idx+1}/{len(lines)}] {proxy[:60]}...")

    if not url:
        if not os.path.exists(KIRO_ACCOUNTS_FILE):
            print("ERROR: No URL and no kiro_accounts.txt")
            return
        with open(KIRO_ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
            accounts = json.load(f)
        idx = (args.index - 1) if args.index else 0
        acc = accounts[idx]
        url = acc.get("stripeUrl", "")
        proxy = proxy or acc.get("proxy", "")
        access_token = acc.get("accessToken", "")
        if not url:
            print(f"ERROR: Account {acc.get('email')} has no stripeUrl.")
            print(f"  Re-run registration with --pay to get it.")
            return
        print(f"Account: {acc.get('email')}")

    # 加载卡
    card = None if args.no_card else load_card()
    if card:
        print(f"Card: ****{card['number'][-4:]}")
    else:
        print("No card loaded, manual input required")

    # 生成账单地址
    country = get_proxy_country(proxy)
    billing = generate_billing_info(country)
    print(f"Billing: {billing['name']}, {billing['city']}, {billing['state']}")

    # 执行
    asyncio.run(auto_pay(url, proxy=proxy, card=card, billing=billing, access_token=access_token))


if __name__ == "__main__":
    main()
