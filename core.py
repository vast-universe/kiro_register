"""
Kiro / AWS Builder ID 自动注册 v10 (纯协议, 无 Playwright)
独立版本 - 移除框架依赖，通过 otp_callback 接入外部邮箱服务

v10 = v8 核心 + HAR 深度分析修复:
  ★ 核心修复: 移除 _setup_signin_js_cookies() 对服务端 cookie 的覆盖
  ★ _capture_cookies 修复: 有 Domain= 的 cookie 存储到裸域名, 避免重复
  ★ Step 4a 后从 workflow-csrf-token 提取 signupCsrfToken 更新 directory-csrf-token
"""
import re, uuid, json, random, string, time, base64, hashlib, secrets
import math, binascii
from urllib.parse import urlparse, parse_qs, quote as url_quote, urlencode
import cbor2
from curl_cffi import requests as curl_requests
from jwcrypto import jwk, jwe

KIRO = "https://app.kiro.dev"
SIGNIN = "https://us-east-1.signin.aws"
DIR_ID = "d-9067642ac7"
PROFILE = "https://profile.aws.amazon.com"

UA_LIST = [
    {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24", "Google Chrome";v="137"',
        "sec-ch-ua-platform": '"Windows"',
        "platform": "Windows"
    },
    {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24", "Google Chrome";v="137"',
        "sec-ch-ua-platform": '"Windows"',
        "platform": "Windows"
    },
    {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24", "Google Chrome";v="137"',
        "sec-ch-ua-platform": '"Windows"',
        "platform": "Windows"
    }
]

# ═══ lsUbid 前缀池 ═══
LSUBID_PREFIXES = ["X10", "X19", "X42", "X55", "X73", "X81", "X96"]

# ═══ XXTEA ═══
# 严格按 kirov2/crypto/xxtea.py 实现，与 AWS signin.aws app.js 逆向一致
XXTEA_KEY = [1888420705, 2576816180, 2347232058, 874813317]
XXTEA_DELTA = 0x9E3779B9
_MASK = 0xFFFFFFFF

def _xxtea_enc(plaintext, key):
    """XXTEA 分组密码加密 — 严格按 app.js doEncrypt 函数实现
    
    1. 字符串 → uint32 数组 (little-endian, 每 4 字节一个 uint32)
    2. XXTEA 加密 (rounds = floor(6 + 52/n))
    3. uint32 数组 → 字节序列 (little-endian)
    """
    if not plaintext:
        return b""
    
    # 步骤 1: 字符串 → uint32 数组 (little-endian)
    # JS: Math.ceil(e.length / 4) 个 uint32
    n = math.ceil(len(plaintext) / 4)
    v = []
    for i in range(n):
        b0 = ord(plaintext[4 * i]) & 0xFF if 4 * i < len(plaintext) else 0
        b1 = ord(plaintext[4 * i + 1]) & 0xFF if 4 * i + 1 < len(plaintext) else 0
        b2 = ord(plaintext[4 * i + 2]) & 0xFF if 4 * i + 2 < len(plaintext) else 0
        b3 = ord(plaintext[4 * i + 3]) & 0xFF if 4 * i + 3 < len(plaintext) else 0
        v.append(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    
    # 步骤 2: XXTEA 加密
    rounds = 6 + 52 // n
    z = v[n - 1]
    total = 0
    
    for _ in range(rounds):
        total = (total + XXTEA_DELTA) & _MASK
        e = (total >> 2) & 3
        
        for p in range(n):
            y = v[(p + 1) % n]
            
            # 标准 XXTEA MX 公式 (严格按 JS 运算符优先级)
            part1 = ((z >> 5) & _MASK) ^ ((y << 2) & _MASK)
            part2 = ((y >> 3) & _MASK) ^ ((z << 4) & _MASK)
            group1 = (part1 + part2) & _MASK
            
            part3 = (total ^ y) & _MASK
            part4 = (key[(p & 3) ^ e] ^ z) & _MASK
            group2 = (part3 + part4) & _MASK
            
            mx = (group1 ^ group2) & _MASK
            
            v[p] = (v[p] + mx) & _MASK
            z = v[p]
    
    # 步骤 3: uint32 数组 → 字节序列 (little-endian)
    result = bytearray()
    for val in v:
        result.append(val & 0xFF)
        result.append((val >> 8) & 0xFF)
        result.append((val >> 16) & 0xFF)
        result.append((val >> 24) & 0xFF)
    
    return bytes(result)

def _gen_perf(nav_start):
    dns = nav_start + random.randint(30, 40)
    conn = dns; ssl = dns
    conn_end = dns + random.randint(1, 3)
    req = conn_end + random.randint(0, 2)
    resp_s = req + random.randint(250, 350)
    resp_e = resp_s
    dom_load = resp_e + random.randint(2, 5)
    dom_int = dom_load + random.randint(2800, 3500)
    dom_cl_s = dom_int; dom_cl_e = dom_int
    dom_comp = dom_cl_e + random.randint(800, 1200)
    load_s = dom_comp; load_e = dom_comp
    return {"connectStart": conn, "secureConnectionStart": ssl,
        "unloadEventEnd": 0, "domainLookupStart": dns,
        "domainLookupEnd": dns, "responseStart": resp_s,
        "connectEnd": conn_end, "responseEnd": resp_e,
        "requestStart": req, "domLoading": dom_load,
        "redirectStart": 0, "loadEventEnd": load_e,
        "domComplete": dom_comp, "navigationStart": nav_start,
        "loadEventStart": load_s,
        "domContentLoadedEventEnd": dom_cl_e,
        "unloadEventStart": 0, "redirectEnd": 0,
        "domInteractive": dom_int, "fetchStart": dns,
        "domContentLoadedEventStart": dom_cl_s}

# ═══ Canvas 数据池（真实采集的 hash + histogram 配对）═══
# TES 会验证 canvas_hash 和 histogramBins 是否来自同一个 canvas 渲染
CANVAS_DATA_POOL = [
    # 样本 1: 真实 Chrome 采集
    (-1436970477, [
     13542, 70, 90, 41, 53, 53, 39, 49, 44, 42, 48, 37, 37, 18, 57, 72,
     53, 48, 56, 120, 38, 28, 27, 34, 24, 28, 57, 9, 21, 29, 18, 66,
     41, 37, 12, 24, 19, 14, 79, 31, 14, 28, 17, 11, 45, 32, 12, 43,
     19, 50, 29, 31, 23, 29, 21, 23, 23, 9, 12, 14, 53, 16, 12, 24,
     13, 12, 25, 48, 18, 12, 15, 45, 24, 44, 45, 19, 12, 11, 53, 17,
     14, 15, 6, 10, 26, 18, 19, 41, 18, 65, 14, 24, 20, 16, 17, 15,
     28, 12, 30, 59, 36, 78, 594, 21, 19, 84, 52, 6, 14, 8, 7, 31,
     16, 5, 6, 14, 9, 39, 8, 23, 46, 22, 17, 14, 18, 7, 29, 10,
     14, 29, 6, 36, 17, 7, 27, 26, 21, 4, 48, 8, 8, 8, 11, 21,
     21, 8, 9, 12, 9, 69, 38, 16, 18, 584, 87, 20, 39, 14, 20, 19,
     18, 15, 19, 22, 17, 13, 8, 20, 32, 6, 24, 25, 8, 41, 5, 10,
     24, 40, 6, 16, 24, 20, 26, 17, 22, 12, 6, 9, 69, 11, 8, 17,
     10, 4, 10, 20, 8, 10, 23, 14, 20, 32, 17, 15, 11, 29, 63, 10,
     18, 11, 22, 91, 9, 15, 23, 15, 19, 56, 9, 13, 22, 12, 46, 41,
     38, 19, 20, 12, 39, 47, 19, 14, 23, 24, 35, 9, 51, 25, 26, 36,
     41, 50, 38, 24, 30, 41, 53, 47, 37, 27, 33, 28, 35, 44, 53, 14472,
    ]),
    # 样本 2: 可以添加更多真实采集的数据
    (-1234567890, [
     13847,42,42,40,62,33,47,29,41,37,32,25,27,53,23,22,31,20,24,
     30,34,20,37,15,21,32,25,26,66,25,16,27,26,19,22,32,38,15,39,35,49,9,29,
     43,16,26,23,15,29,30,36,46,18,29,11,30,24,27,20,27,22,19,20,38,171,32,
     25,33,15,15,6,22,11,39,31,24,18,12,17,34,17,30,17,27,25,28,20,19,19,19,
     24,34,10,24,14,27,28,18,31,27,78,28,512,41,28,22,34,15,26,29,34,16,17,
     21,17,43,17,9,24,34,17,14,26,6,20,39,28,25,230,20,44,19,8,24,18,12,28,
     16,5,28,37,21,11,27,22,30,18,16,25,18,11,25,30,104,13,38,22,22,42,18,23,
     22,32,9,30,18,5,31,34,18,24,17,22,25,12,16,34,18,28,23,15,55,45,18,21,
     31,21,28,22,21,31,30,145,29,19,34,18,21,24,37,30,19,49,34,62,62,23,24,
     21,40,27,30,37,22,38,51,40,37,29,27,53,28,31,27,37,36,40,57,31,22,41,32,
     23,35,28,58,41,45,27,38,36,48,49,30,37,78,56,36,40,62,48,81,70,59,94,13740
    ]),
]

REAL_HIST = [13847,42,42,40,62,33,47,29,41,37,32,25,27,53,23,22,31,20,24,
30,34,20,37,15,21,32,25,26,66,25,16,27,26,19,22,32,38,15,39,35,49,9,29,
43,16,26,23,15,29,30,36,46,18,29,11,30,24,27,20,27,22,19,20,38,171,32,
25,33,15,15,6,22,11,39,31,24,18,12,17,34,17,30,17,27,25,28,20,19,19,19,
24,34,10,24,14,27,28,18,31,27,78,28,512,41,28,22,34,15,26,29,34,16,17,
21,17,43,17,9,24,34,17,14,26,6,20,39,28,25,230,20,44,19,8,24,18,12,28,
16,5,28,37,21,11,27,22,30,18,16,25,18,11,25,30,104,13,38,22,22,42,18,23,
22,32,9,30,18,5,31,34,18,24,17,22,25,12,16,34,18,28,23,15,55,45,18,21,
31,21,28,22,21,31,30,145,29,19,34,18,21,24,37,30,19,49,34,62,62,23,24,
21,40,27,30,37,22,38,51,40,37,29,27,53,28,31,27,37,36,40,57,31,22,41,32,
23,35,28,58,41,45,27,38,36,48,49,30,37,78,56,36,40,62,48,81,70,59,94,13740]

GPU_EXT = [
    "ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_color_buffer_half_float",
    "EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth",
    "EXT_shader_texture_lod", "EXT_texture_compression_bptc",
    "EXT_texture_compression_rgtc", "EXT_texture_filter_anisotropic",
    "EXT_sRGB", "KHR_parallel_shader_compile", "OES_element_index_uint",
    "OES_fbo_render_mipmap", "OES_standard_derivatives", "OES_texture_float",
    "OES_texture_float_linear", "OES_texture_half_float",
    "OES_texture_half_float_linear", "OES_vertex_array_object",
    "WEBGL_color_buffer_float", "WEBGL_compressed_texture_s3tc",
    "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info",
    "WEBGL_debug_shaders", "WEBGL_depth_texture", "WEBGL_draw_buffers",
    "WEBGL_lose_context", "WEBGL_multi_draw",
]

# ═══ 辅助函数 ═══
def _get_gpu_info():
    gpus = [
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 6GB Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x000046A6) Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ]
    return random.choice(gpus)

def _get_screen_info():
    """返回屏幕信息字符串: width-height-availHeight-colorDepth-*-*-*"""
    screens = [
        "1920-1080-1040-24-*-*-*",  # 1080p, 任务栏 40px
        "2560-1440-1400-24-*-*-*",  # 1440p, 任务栏 40px
        "1920-1200-1160-24-*-*-*",  # 1920x1200, 任务栏 40px
        "1366-768-728-24-*-*-*",    # 笔记本, 任务栏 40px
        "1536-864-824-24-*-*-*",    # 笔记本缩放, 任务栏 40px
    ]
    return random.choice(screens)

def _jitter_histogram(bins: list[int]) -> list[int]:
    """给 histogram bins 加微小扰动 (±2), 模拟 canvas 渲染的亚像素不确定性"""
    result = list(bins)
    for i in range(1, 255):
        if random.random() < 0.08:  # ~8% 的 bins 有变化
            delta = random.choice([-2, -1, 1, 2])
            result[i] = max(4, result[i] + delta)
    return result

def _gen_metrics(page_type: str, event_type: str) -> dict:
    """生成 metrics — 参考 kirov2 的区分逻辑：
    - first_load (首次加载): 非零值（代表各模块采集耗时 ms）
    - PageLoad (后续加载): 大部分为零（profile 除外）
    - PageSubmit: 大部分为零，只有 perf 可能非零
    """
    # profile PageLoad 总是有非零 metrics（首次进入 profile 域名）
    if page_type == "profile" and event_type == "PageLoad":
        return {
            "el": 0, "script": 0, "h": 0,
            "batt": random.randint(5, 25),
            "perf": 0, "auto": 0, "tz": 0,
            "fp2": random.randint(1, 8),
            "lsubid": 0,
            "browser": random.randint(0, 3),
            "capabilities": random.randint(1, 8),
            "gpu": 0,
            "dnt": random.randint(0, 3),
            "math": 0, "tts": 0,
            "input": random.randint(8, 30),
            "canvas": random.randint(5, 20),
            "captchainput": 0, "pow": 0,
        }
    
    # PageSubmit 和后续 PageLoad: 大部分为零
    # 真实 [197] send-otp: 只有 perf=1, 其余全 0
    return {
        "el": 0, "script": 0, "h": 0, "batt": 0,
        "perf": random.randint(0, 2) if event_type == "PageSubmit" else 0,
        "auto": 0, "tz": 0, "fp2": 0, "lsubid": 0, "browser": 0,
        "capabilities": 0, "gpu": 0, "dnt": 0, "math": 0, "tts": 0,
        "input": 0, "canvas": 0, "captchainput": 0, "pow": 0,
    }


def _gen_metrics_first_load(page_type: str) -> dict:
    """生成首次加载的 metrics（非零值，代表浏览器模块初始化耗时）
    仅在 stepId="" 的首次 execute 调用时使用
    """
    if page_type == "signup":
        return {
            "el": 0,
            "script": random.randint(0, 2),
            "h": 0,
            "batt": random.randint(0, 5),
            "perf": 0,
            "auto": 0, "tz": 0,
            "fp2": random.randint(0, 3),
            "lsubid": 0,
            "browser": 0, "capabilities": 0,
            "gpu": random.randint(3, 8),
            "dnt": 0, "math": 0, "tts": 0, "input": 0, "canvas": 0,
            "captchainput": 0, "pow": 0,
        }
    else:  # signin
        return {
            "el": 0,
            "script": random.randint(0, 2),
            "h": 0, "batt": 0,
            "perf": 0,
            "auto": random.randint(0, 2),
            "tz": 0, "fp2": 0, "lsubid": 0,
            "browser": random.randint(0, 2),
            "capabilities": 0,
            "gpu": random.randint(3, 8),
            "dnt": 0, "math": 0, "tts": 0, "input": 0, "canvas": 0,
            "captchainput": 0, "pow": 0,
        }

def _gen_interaction(event_type: str, email_len: int = 0) -> dict:
    """生成 interaction 数据 — PageLoad 时全为 0，PageSubmit 时有真实数据"""
    if event_type == "PageLoad":
        return {
            "clicks": 0, "touches": 0, "keyPresses": 0,
            "cuts": 0, "copies": 0, "pastes": 0,
            "keyPressTimeIntervals": [],
            "mouseClickPositions": [],
            "keyCycles": [], "mouseCycles": [], "touchCycles": [],
        }
    else:  # PageSubmit
        n_clicks = random.randint(1, 3)
        n_keys = max(3, email_len // 3 + random.randint(-2, 2)) if email_len > 0 else random.randint(3, 10)
        # intervals 和 cycles 数量 < keyPresses
        n_intervals = random.randint(max(1, n_keys // 3), max(2, n_keys // 2 + 1))
        n_cycles = random.randint(max(2, n_keys // 2), max(3, n_keys * 2 // 3 + 1))
        key_intervals = [random.randint(80, 700) for _ in range(n_intervals)]
        key_cycles = [random.randint(20, 300) for _ in range(n_cycles)]
        return {
            "clicks": n_clicks, "touches": 0, "keyPresses": n_keys,
            "cuts": 0, "copies": 0, "pastes": 0,
            "keyPressTimeIntervals": key_intervals,
            "mouseClickPositions": [
                f"{random.randint(400, 800)},{random.randint(300, 500)}"
                for _ in range(n_clicks)
            ],
            "keyCycles": key_cycles,
            "mouseCycles": [random.randint(50, 150) for _ in range(n_clicks)],
            "touchCycles": [],
        }

def _gen_form_field(start_ms: int, email: str, interaction: dict) -> dict:
    """生成 send-otp 的 form 字段追踪数据"""
    if not email or interaction.get("keyPresses", 0) == 0:
        return {}

    field_ts = start_ms - random.randint(10, 50)
    field_rand = random.randint(1000, 9999)
    field_name = f"formField29-{field_ts}-{field_rand}"

    n_keys = interaction["keyPresses"]
    # form 的 intervals/cycles 和 interaction 几乎相同, 有 ±1 的微小差异
    intervals = [max(1, v + random.randint(-1, 1)) for v in interaction.get("keyPressTimeIntervals", [])]
    cycles = [max(1, v + random.randint(-1, 1)) for v in interaction.get("keyCycles", [])]

    # checksum: CRC32 of email value
    cksum = format(binascii.crc32(email.encode("utf-8")) & 0xFFFFFFFF, "08X")

    return {
        field_name: {
            "clicks": 1,
            "touches": 0,
            "keyPresses": n_keys,
            "cuts": 0,
            "copies": 0,
            "pastes": 0,
            "keyPressTimeIntervals": intervals,
            "mouseClickPositions": [
                f"{random.randint(100, 250)}.5,{random.randint(10, 20)}.5"
            ],
            "keyCycles": cycles,
            "mouseCycles": [random.randint(80, 150)],
            "touchCycles": [],
            "width": 180,
            "height": 32,
            "totalFocusTime": 0,
            "checksum": cksum,
            "autocomplete": False,
            "prefilled": False,
        }
    }

def gen_fwcim(location_url, ubid_main, user_agent, canvas_hash=None, canvas_histogram=None,
              referrer=None, page_type="signin", event_type="PageLoad", email="",
              gpu_vendor=None, gpu_model=None, screen_info=None, lsUbid=None,
              perf_timing=None, cached_start=None, is_first_load=False):
    """
    生成 FWCIM 指纹

    Args:
        page_type: "profile", "signup", "signin"
        event_type: "PageLoad" or "PageSubmit"
        email: 用于 form field 的邮箱（仅 PageSubmit 时需要）
        perf_timing: 缓存的 performance.timing（同一 SPA 页面内应保持不变）
        cached_start: 缓存的 start 时间（同一 SPA 页面内 PageLoad 应保持不变）
        is_first_load: 是否是首次加载（stepId="" 时为 True，生成非零 metrics）
    """
    now_ms = int(time.time() * 1000)

    # performance.timing: SPA 内保持不变
    if perf_timing:
        nav_start = perf_timing["navigationStart"]
    else:
        if event_type == "PageLoad":
            nav_start = now_ms - random.randint(3500, 5000)
        else:
            nav_start = now_ms - random.randint(8000, 15000)

    # start 时间: 同一 SPA 页面内 PageLoad 保持不变
    if cached_start and event_type == "PageLoad":
        start_ms = cached_start
    elif event_type == "PageLoad":
        start_ms = now_ms - random.randint(100, 300)
    else:  # PageSubmit
        start_ms = now_ms - random.randint(3000, 8000)

    # 如果没有提供 canvas 数据，使用配对的数据
    if canvas_hash is None or canvas_histogram is None:
        canvas_data = random.choice(CANVAS_DATA_POOL)
        canvas_hash = canvas_data[0]
        canvas_histogram = list(canvas_data[1])

    # 注意：TES 会精确验证 histogram，不能添加任何 jitter！
    # canvas_histogram 直接使用真实数据，不做任何修改

    # GPU 信息：如果没有提供，则随机选择（但应该在会话级别保持一致）
    if gpu_vendor is None or gpu_model is None:
        gpu_vendor, gpu_model = _get_gpu_info()

    # 屏幕信息：如果没有提供，则随机选择（但应该在会话级别保持一致）
    if screen_info is None:
        screen_info = _get_screen_info()

    # 生成事件类型相关的数据
    # 首次加载用 first_load metrics（非零），后续用普通 metrics（零）
    if is_first_load:
        metrics = _gen_metrics_first_load(page_type)
    else:
        metrics = _gen_metrics(page_type, event_type)
    interaction = _gen_interaction(event_type, len(email) if email else 0)

    # PageSubmit 时生成 form 字段追踪
    form_data = {}
    if event_type == "PageSubmit" and email:
        form_data = _gen_form_field(start_ms, email, interaction)

    # 根据 page_type 设置不同的页面相关字段
    if page_type == "profile":
        # profile.aws.amazon.com: 带 webpack hash 的完整路径
        webpack_hash = f"{random.randint(100000, 999999):06x}"
        dynamic_urls = [f"/dist/main/app_{webpack_hash}.min.js"]
        scripts_elapsed = 0
        history_length = 2 if event_type == "PageLoad" else 3
        is_compatible = True
    elif page_type == "signup":
        # signin.aws signup 页面
        dynamic_urls = ["/assets/js/app.js"]
        scripts_elapsed = 1
        history_length = 5
        is_compatible = True
    else:
        # signin.aws login 页面
        dynamic_urls = ["/assets/js/app.js"]
        scripts_elapsed = 1
        history_length = 1
        is_compatible = False

    # lsUbid: 如果没有提供，则生成新的（但应该在同一域名内保持一致）
    if lsUbid is None:
        lsubid_prefix = random.choice(LSUBID_PREFIXES)
        lsubid_part1 = random.randint(1000000, 9999999)
        lsubid_part2 = random.randint(1000000, 9999999)
        lsubid_timestamp = now_ms // 1000
        lsUbid = f"{lsubid_prefix}-{lsubid_part1}-{lsubid_part2}:{lsubid_timestamp}"

    plugins = ("PDF Viewer Chrome PDF Viewer Chromium PDF Viewer "
               "Microsoft Edge PDF Viewer WebKit built-in PDF "
               "||" + screen_info)

    data = {
        "metrics": metrics,
        "start": start_ms,
        "interaction": interaction,
        "scripts": {"dynamicUrls": dynamic_urls, "inlineHashes": [],
            "elapsed": scripts_elapsed, "dynamicUrlCount": len(dynamic_urls), "inlineHashesCount": 0},
        "history": {"length": history_length},
        "battery": {},
        "performance": {"timing": perf_timing or _gen_perf(nav_start)},
        "automation": {"wd": {"properties": {"document": [], "window": [],
            "navigator": []}}, "phantom": {"properties": {"window": []}}},
        "end": now_ms,
        "timeZone": 8,
        "flashVersion": None,
        "plugins": plugins, "dupedPlugins": plugins,
        "screenInfo": screen_info,
        "lsUbid": lsUbid,
        "referrer": referrer or "https://view.awsapps.com/",
        "userAgent": user_agent,
        "location": location_url,
        "webDriver": False,
        "capabilities": {"css": {"textShadow": 1, "WebkitTextStroke": 1,
            "boxShadow": 1, "borderRadius": 1, "borderImage": 1, "opacity": 1,
            "transform": 1, "transition": 1},
            "js": {"audio": True, "geolocation": True,
            "localStorage": "supported", "touch": False, "video": True,
            "webWorker": True}, "elapsed": 0},
        "gpu": {"vendor": gpu_vendor,
            "model": gpu_model,
            "extensions": GPU_EXT},
        "dnt": None,
        "math": {"tan": "-1.4214488238747245",
            "sin": "0.8178819121159085", "cos": "-0.5753861119575491"},
    }

    # timeToSubmit 字段：只有 profile 页面有（参考 kirov2 真实抓包分析）
    # signin/signup 页面没有这个字段！
    if page_type == "profile":
        # profile: PageLoad 时很小 (1-5), PageSubmit 时是实际停留时间
        if event_type == "PageLoad":
            data["timeToSubmit"] = random.randint(1, 5)
        else:
            data["timeToSubmit"] = now_ms - start_ms

    # 继续添加剩余字段
    data.update({
        "form": form_data,
        "canvas": {"hash": canvas_hash, "emailHash": None,
            "histogramBins": canvas_histogram},
        "token": {"isCompatible": is_compatible, "pageHasCaptcha": 0},
        "auth": {"form": {"method": "get"}},
        "errors": [], "version": "4.0.0"})

    js = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    crc = format(binascii.crc32(js.encode()) & 0xFFFFFFFF, "08X")
    plain = crc + "#" + js
    enc = _xxtea_enc(plain, XXTEA_KEY)
    b64 = base64.b64encode(enc).decode()
    return "ECdITeCs:" + b64


# ═══ JWE 密码加密 ═══
def encrypt_password_jwe(password, public_key_jwk):
    key = jwk.JWK(**public_key_jwk)
    protected = json.dumps({
        "alg": "RSA-OAEP-256",
        "kid": public_key_jwk["kid"],
        "enc": "A256GCM",
        "cty": "enc",
        "typ": "application/aws+signin+jwe"
    }, separators=(",", ":"))
    now = int(time.time())
    plaintext = json.dumps({
        "iss": "us-east-1.signin",
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "exp": now + 300,
        "aud": "us-east-1.AWSPasswordService",
        "password": password
    }, separators=(",", ":"))
    token = jwe.JWE(plaintext.encode("utf-8"),
                    recipient=key,
                    protected=protected)
    return token.serialize(compact=True)


# ═══ 辅助函数 ═══
def _pkce():
    v = secrets.token_urlsafe(43)
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()
        ).rstrip(b"=").decode()
    return v, c

def _vid():
    t = int(time.time() * 1000)
    r = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"{t}-{r}"

def _pwd():
    return secrets.token_urlsafe(12) + "!A1"

def _uuid():
    return str(uuid.uuid4())

def _ubid():
    return f"{random.randint(100, 999)}-{random.randint(1000000, 9999999)}-{random.randint(1000000, 9999999)}"

def _gen_random_name():
    first_names = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"


class KiroRegister:
    def __init__(self, proxy=None, tag="REG", impersonate="chrome120"):
        self.tag = tag
        self.proxy = proxy

        # Pick a random UA and platform
        self.ua_data = random.choice(UA_LIST)
        self.ua = {
            "user-agent": self.ua_data["user-agent"],
            "sec-ch-ua": self.ua_data["sec-ch-ua"],
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": self.ua_data["sec-ch-ua-platform"],
            "dnt": "1",
        }
        self.platform = self.ua_data["platform"]

        # Determine impersonate: chrome137 matches our UA_LIST
        self.s = curl_requests.Session(impersonate=impersonate)
        if proxy:
            self.s.proxies = {"https": proxy, "http": proxy}
        
        # 普通 session（不带 impersonate），用于 OIDC/Portal 等不检查 TLS 指纹的 API
        self.s_plain = curl_requests.Session()
        if proxy:
            self.s_plain.proxies = {"https": proxy, "http": proxy}
        
        self.cv, self.cc = _pkce()
        self.state = _uuid()
        self.vid = _vid()
        self.wsh = None
        self.sid = None
        self.profile_wf_id = None
        self.profile_wf_state = None
        self._awsd2c_token = None
        self._tes_visitor_id = None
        self._profile_ubid = _ubid()
        self._platform_ubid = _ubid()
        self._aws_ubid_main = None

        # 使用真实配对的 canvas 数据
        canvas_data = random.choice(CANVAS_DATA_POOL)
        self._canvas_hash = canvas_data[0]
        self._canvas_histogram = list(canvas_data[1])

        # GPU 信息在整个会话中保持一致
        self._gpu_vendor, self._gpu_model = _get_gpu_info()

        # 屏幕信息在整个会话中保持一致
        self._screen_info = _get_screen_info()

        # lsUbid: 不同域名各自独立，但在同一域名内保持一致
        # signin.aws 和 profile.aws 各自有一个 lsUbid
        self._lsubid_signin = None
        self._lsubid_profile = None

        # 指纹上下文缓存 — 同一 SPA 页面内保持一致（参考 kirov2 FingerprintContext）
        self._perf_timing_signin = None  # signin 域名的 performance.timing
        self._perf_timing_profile = None  # profile 域名的 performance.timing
        self._start_time_signin = None  # signin 域名的 start 时间
        self._start_time_profile = None  # profile 域名的 start 时间
        self._webpack_hash = secrets.token_hex(5)  # profile 页面的 webpack hash（会话内固定）

        self._profile_load_ts = 0
        self._portal_csrf_token = None
        self._directory_csrf_token = None
        self._signup_csrf_token = None
        self._orchestrator_id = None
        self._callback_url = None
        self._workflow_result_handle = None
        self._step11_state = None
        self._sso_state = None  # state from step10 redirect, used for SSO token

        # Device authorization (在注册前初始化)
        self._device_client_id = None
        self._device_client_secret = None
        self._device_code = None
        self._user_code = None

    def log(self, msg):
        print(f"[{self.tag}] {msg}")

    def _capture_cookies(self, resp):
        hostname = urlparse(str(resp.url)).hostname or "us-east-1.signin.aws"
        for k, v in resp.headers.multi_items():
            if k.lower() != "set-cookie": continue
            m = re.match(r"([^=]+)=([^;]*)", v)
            if not m: continue
            name, value = m.group(1), m.group(2)
            dm = re.search(r"[Dd]omain=([^;,\s]+)", v)
            pm = re.search(r"[Pp]ath=([^;,\s]+)", v)
            path = pm.group(1) if pm else "/"
            if name == "aws-ubid-main": self._aws_ubid_main = value
            if dm:
                domain = dm.group(1).lstrip(".")
                dot_domain = "." + domain
                try: self.s.cookies.delete(name, domain=dot_domain, path=path)
                except: pass
                self.s.cookies.set(name, value, domain=domain, path=path)
            else:
                self.s.cookies.set(name, value, domain=hostname, path=path)

    def _setup_signin_js_cookies(self, step_id=None):
        domain = "us-east-1.signin.aws"
        try: self.s.cookies.delete("platform-ubid", domain=domain, path="/platform")
        except: pass
        self.s.cookies.set("platform-ubid", self._platform_ubid,
                           domain=domain, path="/platform")

    def _update_directory_csrf_with_signup(self):
        from urllib.parse import unquote as url_unquote
        domain = "us-east-1.signin.aws"
        wf_by_domain = {}
        dir_by_domain = {}
        dir_csrf_path = f"/platform/{DIR_ID}"
        for c in self.s.cookies.jar:
            if "signin.aws" not in (c.domain or ""): continue
            if c.name == "workflow-csrf-token":
                wf_by_domain[c.domain] = c.value
            elif c.name == "directory-csrf-token":
                dir_by_domain[c.domain] = (c.value, c.path)
        wf_csrf_val = wf_by_domain.get(domain) or wf_by_domain.get(f".{domain}")
        dir_entry = dir_by_domain.get(domain) or dir_by_domain.get(f".{domain}")
        dir_csrf_val = dir_entry[0] if dir_entry else None
        if dir_entry:
            dir_csrf_path = dir_entry[1] or dir_csrf_path
        if not wf_csrf_val or not dir_csrf_val:
            return
        try:
            wf_decoded = json.loads(url_unquote(wf_csrf_val))
            dir_decoded = json.loads(url_unquote(dir_csrf_val))
            signup_token = wf_decoded.get("signupCsrfToken")
            if signup_token and "signupCsrfToken" not in dir_decoded:
                dir_decoded["signupCsrfToken"] = signup_token
                new_val = url_quote(json.dumps(dir_decoded, separators=(",", ":")), safe="")
                for c in list(self.s.cookies.jar):
                    if c.name == "directory-csrf-token":
                        try: self.s.cookies.delete(c.name, domain=c.domain, path=c.path)
                        except: pass
                self.s.cookies.set("directory-csrf-token", new_val,
                                   domain=domain, path=dir_csrf_path)
                self.log(f"  directory-csrf-token updated with signupCsrfToken")
        except Exception as e:
            self.log(f"  warning: update directory-csrf-token failed: {e}")

    def _get_lsUbid(self, page_type: str) -> str:
        """获取或生成对应域名的 lsUbid

        lsUbid 在同一域名内保持一致，不同域名各自独立
        signin.aws 和 profile.aws 各自有一个 lsUbid
        """
        if page_type == "profile":
            if not self._lsubid_profile:
                lsubid_prefix = random.choice(LSUBID_PREFIXES)
                lsubid_part1 = random.randint(1000000, 9999999)
                lsubid_part2 = random.randint(1000000, 9999999)
                lsubid_timestamp = int(time.time())
                self._lsubid_profile = f"{lsubid_prefix}-{lsubid_part1}-{lsubid_part2}:{lsubid_timestamp}"
            return self._lsubid_profile
        else:
            # signin 或 signup
            if not self._lsubid_signin:
                lsubid_prefix = random.choice(LSUBID_PREFIXES)
                lsubid_part1 = random.randint(1000000, 9999999)
                lsubid_part2 = random.randint(1000000, 9999999)
                lsubid_timestamp = int(time.time())
                self._lsubid_signin = f"{lsubid_prefix}-{lsubid_part1}-{lsubid_part2}:{lsubid_timestamp}"
            return self._lsubid_signin

    def _gen_signin_fwcim(self, page_type="signup", event_type="PageLoad", email="", _first_load=False):
        # location URL 根据 page_type 区分（参考 kirov2 _fp 方法）
        if page_type == "signin":
            loc_url = f"{SIGNIN}/platform/{DIR_ID}/login?workflowStateHandle={self.wsh or ''}"
        else:  # signup
            loc_url = f"{SIGNIN}/platform/{DIR_ID}/signup?workflowStateHandle={self.wsh or ''}"
        
        ubid = self._aws_ubid_main or self._platform_ubid
        lsUbid = self._get_lsUbid(page_type)
        
        # 使用缓存的 timing（同一域名内保持一致）
        if self._perf_timing_signin is None:
            now_ms = int(time.time() * 1000)
            nav_start = now_ms - random.randint(3500, 5000)
            self._perf_timing_signin = _gen_perf(nav_start)
            self._start_time_signin = now_ms - random.randint(100, 300)
        
        return gen_fwcim(loc_url, ubid, self.ua["user-agent"], self._canvas_hash,
                         self._canvas_histogram, page_type=page_type,
                         event_type=event_type, email=email,
                         gpu_vendor=self._gpu_vendor, gpu_model=self._gpu_model,
                         screen_info=self._screen_info, lsUbid=lsUbid,
                         perf_timing=self._perf_timing_signin,
                         cached_start=self._start_time_signin,
                         is_first_load=_first_load)

    def _safe_cookie_list(self, domain_filter=None):
        result = []
        for c in self.s.cookies.jar:
            if domain_filter and domain_filter not in (c.domain or ""):
                continue
            result.append((c.name, c.value, c.domain, c.path))
        return result

    def _exec(self, step_id, inputs=None, prefix="", action_id=None,
              extra_fields=None):
        url = f"{SIGNIN}/platform/{DIR_ID}{prefix}/api/execute"
        body = {"stepId": step_id, "workflowStateHandle": self.wsh or "",
              "inputs": inputs or [], "requestId": _uuid()}
        if action_id: body["actionId"] = action_id
        # 始终包含 visitorId（参考 kirov2，每个 execute 调用都带）
        if self._tes_visitor_id:
            body["visitorId"] = self._tes_visitor_id
        if extra_fields: body.update(extra_fields)
        ref = f"{SIGNIN}/platform/{DIR_ID}/login?workflowStateHandle={self.wsh or ''}"
        rid = body["requestId"]
        h = {**self.ua, "accept": "application/json, text/plain, */*",
           "content-type": "application/json",
           "origin": SIGNIN, "referer": ref,
           "x-amzn-requestid": rid,
           "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
           "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors",
           "sec-fetch-dest": "empty", "priority": "u=1, i"}
        self.log(f"  POST {url}")
        self.log(f"  stepId='{step_id}' actionId={action_id} wsh={str(self.wsh)[:40]}...")
        r = self.s.post(url, headers=h, json=body)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if r.status_code != 200:
            self.log(f"  ERROR {r.status_code}: {r.text[:500]}"); return None
        try: d = r.json()
        except: self.log(f"  ERROR non-JSON: {r.text[:300]}"); return None
        if d.get("workflowStateHandle"): self.wsh = d["workflowStateHandle"]
        if d.get("stepId") is not None: self.sid = d["stepId"]
        self.log(f"  -> sid={self.sid} wsh={str(self.wsh)[:40]}...")
        self.log(f"  Resp: {json.dumps(d, ensure_ascii=False)[:400]}")
        return d

    def _setup_profile_cookies(self):
        self.s.cookies.set("i18next", "zh-CN",
            domain="profile.aws.amazon.com", path="/")
        if self._aws_ubid_main:
            self.s.cookies.set("aws-ubid-main", self._aws_ubid_main,
                domain=".amazon.com", path="/")
        awsccc = json.dumps({"e": 1, "p": 1, "f": 1, "a": 1, "i": _uuid(), "v": "1"},
            separators=(",", ":"))
        self.s.cookies.set("awsccc", base64.b64encode(awsccc.encode()).decode(),
            domain="profile.aws.amazon.com", path="/")
        self.s.cookies.set("aws-user-profile-ubid", self._profile_ubid,
            domain="profile.aws.amazon.com", path="/")

    def _browser_data(self, page_name=None, event_type="PageLoad", email=""):
        elapsed = 0
        if self._profile_load_ts:
            elapsed = int((time.time() - self._profile_load_ts) * 1000)

        # Determine location and referrer based on context
        if self.profile_wf_id and page_name:
            if page_name == "EMAIL_COLLECTION":
                hash_fragment = "#/signup/enter-email"
            elif page_name == "EMAIL_VERIFICATION":
                hash_fragment = "#/signup/verify-email"
            else:
                hash_fragment = "#/signup/start"
            loc_url = f"{PROFILE}/{hash_fragment}?workflowID={self.profile_wf_id}"
            ref_url = f"{SIGNIN}/platform/{DIR_ID}/signup?workflowStateHandle={self.wsh or ''}"
            page_type = "profile"
        else:
            loc_url = f"{SIGNIN}/platform/{DIR_ID}/login?workflowStateHandle={self.wsh or ''}"
            ref_url = "https://view.awsapps.com/"
            page_type = "signin"

        # 使用缓存的 profile timing（同一 SPA 页面内保持一致）
        if page_type == "profile":
            if self._perf_timing_profile is None:
                now_ms = int(time.time() * 1000)
                nav_start = now_ms - random.randint(3500, 5000)
                self._perf_timing_profile = _gen_perf(nav_start)
                self._start_time_profile = now_ms - random.randint(30, 80)
            perf_timing = self._perf_timing_profile
            cached_start = self._start_time_profile
        else:
            perf_timing = self._perf_timing_signin
            cached_start = self._start_time_signin

        ubid_main = self._aws_ubid_main or _ubid()
        lsUbid = self._get_lsUbid(page_type)
        fp = gen_fwcim(loc_url, ubid_main, self.ua["user-agent"], self._canvas_hash,
                       self._canvas_histogram, referrer=ref_url, page_type=page_type,
                       event_type=event_type, email=email,
                       gpu_vendor=self._gpu_vendor, gpu_model=self._gpu_model,
                       screen_info=self._screen_info, lsUbid=lsUbid,
                       perf_timing=perf_timing, cached_start=cached_start)
        bd = {"attributes": {
                "fingerprint": fp,
                "eventTimestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "timeSpentOnPage": str(max(elapsed, random.randint(2000, 5000))),
                "eventType": event_type,
                "ubid": self._profile_ubid,
            }, "cookies": {}}
        if page_name: bd["attributes"]["pageName"] = page_name
        if self._tes_visitor_id:
            bd["attributes"]["visitorId"] = self._tes_visitor_id
        return bd

    def _profile_headers(self):
        h = {**self.ua, "accept": "*/*", "accept-language": "zh-CN,zh;q=0.9",
            "content-type": "application/json;charset=UTF-8",
            "origin": PROFILE, "priority": "u=1, i",
            "referer": f"{PROFILE}/?workflowID={self.profile_wf_id or ''}",
            "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty"}
        if self._awsd2c_token:
            h["x-awsd2c-token"] = self._awsd2c_token
        if self._tes_visitor_id:
            h["x-awsd2c-visitor-id"] = self._tes_visitor_id
        return h

    def _profile_post(self, endpoint, payload):
        url = f"{PROFILE}{endpoint}"
        h = self._profile_headers()
        self.log(f"  POST {url}")
        r = self.s.post(url, headers=h, json=payload)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if r.status_code not in (200, 201):
            self.log(f"  ERROR {r.status_code}: {r.text[:500]}"); return None
        try:
            d = r.json()
            self.log(f"  Resp: {json.dumps(d, ensure_ascii=False)[:400]}")
            return d
        except: return {}

    # ═══ Step 0: 预先注册 OIDC Client 和 Device Authorization ═══
    def step0_init_device_auth(self):
        """在注册前初始化 device authorization（参考 kiro纯协议）"""
        OIDC = "https://oidc.us-east-1.amazonaws.com"
        self.log("Step 0: Pre-register OIDC client and device authorization...")

        # 0a: 注册 OIDC client
        self.log("  0a: POST oidc/client/register...")
        reg_h = {
            "content-type": "application/json",
            "user-agent": "aws-sdk-rust/1.3.9 os/windows lang/rust/1.87.0",
            "x-amz-user-agent": "aws-sdk-rust/1.3.9 ua/2.1 api/ssooidc/1.88.0 "
                "os/windows lang/rust/1.87.0 m/E app/AmazonQ-For-CLI",
            "amz-sdk-request": "attempt=1; max=3",
            "amz-sdk-invocation-id": _uuid(),
        }
        reg_body = {
            "clientName": "Amazon Q Developer for command line",
            "clientType": "public",
            "scopes": ["codewhisperer:completions", "codewhisperer:analysis",
                       "codewhisperer:conversations"],
            "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
            "issuerUrl": "https://identitycenter.amazonaws.com/ssoins-722374e5d5e7e3e0",
        }
        r = self.s.post(f"{OIDC}/client/register", headers=reg_h, json=reg_body)
        self.log(f"  Status: {r.status_code}")
        if r.status_code != 200:
            self.log(f"  ERROR client/register failed: {r.text[:300]}")
            return False
        reg_resp = r.json()
        self._device_client_id = reg_resp.get("clientId", "")
        self._device_client_secret = reg_resp.get("clientSecret", "")
        if not self._device_client_id or not self._device_client_secret:
            self.log(f"  ERROR no clientId/clientSecret")
            return False
        self.log(f"  OK clientId={self._device_client_id[:40]}...")

        # 0b: 发起 device authorization
        self.log("  0b: POST oidc/device_authorization...")
        da_h = {**reg_h, "amz-sdk-invocation-id": _uuid()}
        da_body = {
            "clientId": self._device_client_id,
            "clientSecret": self._device_client_secret,
            "startUrl": "https://view.awsapps.com/start"
        }
        r = self.s.post(f"{OIDC}/device_authorization", headers=da_h, json=da_body)
        self.log(f"  Status: {r.status_code}")
        if r.status_code != 200:
            self.log(f"  ERROR device_authorization failed: {r.text[:300]}")
            return False
        da_resp = r.json()
        self._device_code = da_resp.get("deviceCode", "")
        self._user_code = da_resp.get("userCode", "")
        if not self._device_code or not self._user_code:
            self.log(f"  ERROR no deviceCode/userCode")
            return False
        self.log(f"  OK userCode={self._user_code}, deviceCode={self._device_code[:40]}...")
        return True

    # ═══ Step 1: Kiro InitiateLogin ═══
    def step1_kiro_init(self):
        self.log("Step 1: Kiro InitiateLogin...")
        body = cbor2.dumps({"idp": "BuilderId",
            "redirectUri": f"{KIRO}/signin/oauth", "state": self.state,
            "codeChallenge": self.cc, "codeChallengeMethod": "S256"})
        
        # Consistent SDK user agent based on our chosen platform
        sdk_ua = f"aws-sdk-js/1.0.0 ua/2.1 os/{self.platform} lang/js md/browser#Chromium_131 m/N,M,E"
        
        h = {**self.ua, "accept": "application/cbor", "content-type": "application/cbor",
           "smithy-protocol": "rpc-v2-cbor", "origin": KIRO,
           "referer": f"{KIRO}/signin", "x-kiro-visitorid": self.vid,
           "amz-sdk-invocation-id": _uuid(), "amz-sdk-request": "attempt=1; max=1",
           "x-amz-user-agent": sdk_ua}
        r = self.s.post(f"{KIRO}/service/KiroWebPortalService/operation/InitiateLogin",
            headers=h, data=body, cookies={"kiro-visitor-id": self.vid})
        if r.status_code != 200: self.log(f"  ERROR {r.status_code}"); return None
        try: d = cbor2.loads(r.content)
        except: d = r.json()
        redir = d.get("redirectUrl")
        if not redir: self.log(f"  ERROR no redirectUrl: {d}"); return None
        self.log(f"  OK {redir[:100]}...")
        return redir

    # ═══ Step 2: 获取 workflowStateHandle (通过 Portal API) ═══
    def step2_get_wsh(self, redir_url):
        self.log("Step 2: Portal 初始化...")
        
        PORTAL = "https://portal.sso.us-east-1.amazonaws.com"
        VIEW = "https://view.awsapps.com"
        
        # 设置 awsccc cookie
        awsccc = json.dumps({"e": 1, "p": 1, "f": 1, "a": 1, "i": _uuid(), "v": "1"},
                            separators=(",", ":"))
        awsccc_b64 = base64.b64encode(awsccc.encode()).decode()
        self.s.cookies.set("awsccc", awsccc_b64, domain="us-east-1.signin.aws", path="/")
        
        # 2a: 通过 Portal API 获取 wsh（参考 kirov2 step4）
        redirect_target = f"{VIEW}/start/#/device?user_code={self._user_code}" if self._user_code else f"{VIEW}/start/#/"
        portal_url = f"{PORTAL}/login?directory_id=view&redirect_url={url_quote(redirect_target, safe='')}"
        
        portal_h = {
            **self.ua,
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "origin": VIEW,
            "referer": f"{VIEW}/",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        }
        
        self.log(f"  2a: GET {PORTAL}/login...")
        r = self.s.get(portal_url, headers=portal_h)
        self._capture_cookies(r)
        self.log(f"  Status: {r.status_code}")
        
        if r.status_code == 200:
            data = r.json()
            rurl = data.get("redirectUrl", "")
            csrf_token = data.get("csrfToken")
            
            if csrf_token:
                self.s.cookies.set("loginCsrfToken", str(csrf_token), 
                                   domain="portal.sso.us-east-1.amazonaws.com", path="/")
                self._portal_csrf_token = csrf_token
                self.log(f"  OK csrfToken={str(csrf_token)[:40]}...")
            
            if "workflowStateHandle=" in rurl:
                self.wsh = rurl.split("workflowStateHandle=")[1].split("&")[0]
                self._login_wsh = self.wsh
                self.log(f"  OK wsh={self.wsh[:40]}...")
            else:
                self.log(f"  ERROR no workflowStateHandle in redirectUrl: {rurl[:200]}")
                return False
        else:
            # Fallback: 直接 follow redirects（旧方式）
            self.log(f"  Portal API failed ({r.status_code}), falling back to redirect chain...")
            r = self.s.get(redir_url, headers=self.ua, allow_redirects=True)
            final_url = str(r.url)
            p = urlparse(final_url)
            qs = parse_qs(p.query)
            wsh = (qs.get("workflowStateHandle") or [None])[0]
            if not wsh:
                self.log("  ERROR no workflowStateHandle")
                return False
            self.wsh = wsh
            self._login_wsh = self.wsh
            self._capture_cookies(r)
        
        # 2b: 获取 D2C token（进入 signin 域名后立即获取）— 这样 step3 就有 visitorId
        login_url = f"{SIGNIN}/platform/{DIR_ID}/login?workflowStateHandle={self.wsh}"
        self._refresh_d2c_token(SIGNIN, login_url)
        
        self._setup_signin_js_cookies()
        self.log(f"  OK wsh={self.wsh[:40]}...")
        return True

    # ═══ Step 3: signin.aws -> SIGNUP ═══
    def step3_signin_flow(self, email):
        self.log("Step 3: signin.aws workflow...")
        
        # 3a: 首次加载用 first_load 指纹（metrics 有非零值，代表浏览器首次采集）
        fp_first = self._gen_signin_fwcim(page_type="signin", event_type="PageLoad", _first_load=True)
        fp_i_first = {"input_type": "FingerPrintRequestInput", "fingerPrint": fp_first}
        self.log("  3a: init (stepId='')...")
        if not self._exec("", inputs=[fp_i_first]): return None
        
        # 3b: start 用 PageLoad 指纹（后续加载，metrics 为零）
        fp_load = self._gen_signin_fwcim(page_type="signin", event_type="PageLoad")
        fp_i_load = {"input_type": "FingerPrintRequestInput", "fingerPrint": fp_load}
        self.log("  3b: start -> get-identity-user...")
        if not self._exec("start", inputs=[fp_i_load]): return None
        
        # 3c: SIGNUP — 带 UserEventRequestInput（参考 kirov2 step6）
        fp_submit = self._gen_signin_fwcim(page_type="signin", event_type="PageSubmit", email=email)
        fp_i_submit = {"input_type": "FingerPrintRequestInput", "fingerPrint": fp_submit}
        usr_i = {"input_type": "UserRequestInput", "username": email}
        evt_i = {"input_type": "UserEventRequestInput",
                 "directoryId": DIR_ID,
                 "userName": email,
                 "userEvents": [{"input_type": "UserEvent",
                                 "eventType": "PAGE_SUBMIT",
                                 "pageName": "IDENTIFICATION",
                                 "timeSpentOnPage": random.randint(4000, 8000)}]}
        self.log("  3c: SIGNUP...")
        r = self._exec("get-identity-user", inputs=[usr_i, evt_i, fp_i_submit], action_id="SIGNUP")
        if not r: return None
        redir = r.get("redirect", {}).get("url")
        if redir:
            self.log(f"  OK signup redirect: {redir[:100]}...")
            m = re.search(r"workflowStateHandle=([^&#]+)", redir)
            if m: self.wsh = m.group(1)
        return r

    # ═══ Step 4: signup -> profile.aws redirect ═══
    def step4_signup_flow(self, email):
        self.log("Step 4: signup workflow...")
        # signup 域名的首次加载指纹（first_load metrics）
        fp_first = self._gen_signin_fwcim(page_type="signup", event_type="PageLoad", _first_load=True)
        fp_i_first = {"input_type": "FingerPrintRequestInput", "fingerPrint": fp_first}
        usr_i = {"input_type": "UserRequestInput", "username": email}
        self.log("  4a: signup init...")
        if not self._exec("", inputs=[usr_i, fp_i_first], prefix="/signup"): return None
        self._update_directory_csrf_with_signup()
        
        # signup start 用 PageLoad 指纹（后续加载，metrics 为零）
        fp_load = self._gen_signin_fwcim(page_type="signup", event_type="PageLoad")
        fp_i_load = {"input_type": "FingerPrintRequestInput", "fingerPrint": fp_load}
        self.log("  4b: signup start...")
        r = self._exec("start", inputs=[usr_i, fp_i_load], prefix="/signup")
        if not r: return None
        redir = r.get("redirect", {}).get("url", "")
        if "profile.aws" in redir:
            self.log(f"  OK profile redirect: {redir[:100]}...")
            m = re.search(r"workflowID=([^&#]+)", redir)
            if m:
                self.profile_wf_id = m.group(1)
                self.log(f"  workflowID: {self.profile_wf_id}")
        self._signup_wsh = self.wsh
        return r

    # ═══ Step 5: TES token ═══
    def step5_get_tes_token(self):
        self.log("Step 5: TES token (D2C)...")
        
        # 加载 signin.aws 资源（模拟真实浏览器）
        self.log("  loading signin.aws resources...")
        try:
            for path in ["/assets/js/app.js"]:
                r = self.s.get(f"{SIGNIN}{path}", headers={**self.ua, "accept": "*/*",
                    "referer": f"{SIGNIN}/platform/{DIR_ID}/login"}, timeout=10)
                self._capture_cookies(r)
        except Exception as e:
            self.log(f"  warning during resource loading: {e}")

        # D2C Token 获取 — 参考 kirov2 的 _d2c_token 实现
        # 真实浏览器发送 {"token": old_token} 或 {} (首次)
        token_url = "https://vs.aws.amazon.com/token"
        h = {**self.ua, "accept": "*/*", "content-type": "application/json",
             "origin": SIGNIN, "referer": f"{SIGNIN}/platform/{DIR_ID}/login?workflowStateHandle={self.wsh or ''}",
             "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors",
             "sec-fetch-dest": "empty", "priority": "u=1, i"}
        
        # 添加 awsccc cookie
        awsccc_val = None
        for c in self.s.cookies.jar:
            if c.name == "awsccc":
                awsccc_val = c.value
                break
        
        token = None
        # 首次获取：发送空 body（真实浏览器行为）
        self.log("  POST vs.aws.amazon.com/token (empty body)...")
        try:
            r = self.s.post(token_url, headers=h, json={}, timeout=15)
            self._capture_cookies(r)
            if r.status_code == 200:
                token = r.json().get("token")
        except Exception as e:
            self.log(f"  POST /token failed: {e}")

        if token:
            self.log(f"  OK awsd2c-token: {token[:60]}...")
            self._awsd2c_token = token
            try:
                parts = token.split(".")
                if len(parts) >= 2:
                    pb = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    pb = pb.replace("-", "+").replace("_", "/")
                    jp = json.loads(base64.b64decode(pb))
                    self._tes_visitor_id = jp.get("vid")
                    self.log(f"  OK visitorId: {self._tes_visitor_id}")
            except Exception as e:
                self.log(f"  warning: failed to extract vid from token: {e}")
            
            self.s.cookies.set("awsd2c-token", token, domain="profile.aws.amazon.com", path="/")
            self.s.cookies.set("awsd2c-token-c", token, domain="profile.aws.amazon.com", path="/")
            return token
        
        self.log("  ERROR: failed to get TES token")
        return None

    def _refresh_d2c_token(self, origin, referer):
        """刷新 D2C token — 进入新域名时调用（参考 kirov2 _d2c_token）"""
        token_url = "https://vs.aws.amazon.com/token"
        h = {**self.ua, "accept": "*/*", "content-type": "application/json",
             "origin": origin, "referer": referer,
             "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors",
             "sec-fetch-dest": "empty", "priority": "u=1, i"}
        
        # 如果已有 token，发送 {"token": old_token}
        payload = {"token": self._awsd2c_token} if self._awsd2c_token else {}
        
        try:
            r = self.s.post(token_url, headers=h, json=payload, timeout=15)
            self._capture_cookies(r)
            if r.status_code == 200:
                token = r.json().get("token")
                if token:
                    self._awsd2c_token = token
                    # 提取 visitor_id
                    try:
                        parts = token.split(".")
                        if len(parts) >= 2:
                            pb = parts[1] + "=" * (4 - len(parts[1]) % 4)
                            pb = pb.replace("-", "+").replace("_", "/")
                            jp = json.loads(base64.b64decode(pb))
                            if jp.get("vid"):
                                self._tes_visitor_id = jp["vid"]
                    except:
                        pass
                    self.s.cookies.set("awsd2c-token", token, domain="profile.aws.amazon.com", path="/")
                    self.s.cookies.set("awsd2c-token-c", token, domain="profile.aws.amazon.com", path="/")
                    self.log(f"  D2C token refreshed: {token[:40]}...")
                    return token
        except Exception as e:
            self.log(f"  D2C token refresh failed: {e}")
        return None

    # ═══ Step 6: profile.aws page load + /api/start ═══
    def step6_profile_load(self):
        self.log("Step 6: profile.aws page load...")
        if not self.profile_wf_id:
            self.log("  ERROR no workflowID"); return None
        self._setup_profile_cookies()
        self.log("  6a: GET profile page...")
        # 重试机制（代理可能偶尔断连）
        for attempt in range(3):
            try:
                r = self.s.get(f"{PROFILE}?workflowID={self.profile_wf_id}",
                    headers={**self.ua, "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                             "referer": f"{SIGNIN}/",
                             "sec-fetch-dest": "document", "sec-fetch-mode": "navigate"},
                    allow_redirects=True, timeout=30)
                break
            except Exception as e:
                if attempt < 2:
                    self.log(f"  retry {attempt+1}: {e}")
                    time.sleep(2)
                else:
                    raise
        self._capture_cookies(r)
        self._profile_load_ts = time.time()
        self.log(f"  page status: {r.status_code}")
        
        # 6a.5: 进入 profile 域名后刷新 D2C token（参考 kirov2 step7.8）
        profile_url = f"{PROFILE}/?workflowID={self.profile_wf_id}"
        self._refresh_d2c_token(PROFILE, profile_url)
        
        time.sleep(random.uniform(1.0, 2.5))
        self.log("  6d: POST /api/start...")
        payload = {"workflowID": self.profile_wf_id,
                 "browserData": self._browser_data()}
        r = self._profile_post("/api/start", payload)
        if r and r.get("workflowState"):
            self.profile_wf_state = r["workflowState"]
            self.log(f"  OK workflowState: {self.profile_wf_state}")
        return r

    # ═══ Step 7: send-otp ═══
    def step7_send_otp(self, email):
        self.log(f"Step 7: send-otp to {email}...")
        time.sleep(random.uniform(2.0, 4.0))
        payload = {"workflowState": self.profile_wf_state, "email": email,
            "browserData": self._browser_data(page_name="EMAIL_COLLECTION",
                event_type="PageSubmit", email=email)}
        return self._profile_post("/api/send-otp", payload)

    # ═══ Step 8: create-identity (OTP verify + create identity) ═══
    def step8_create_identity(self, otp, email, full_name):
        self.log("Step 8: create-identity...")
        time.sleep(random.uniform(1.0, 3.0))
        payload = {
            "workflowState": self.profile_wf_state,
            "userData": {"email": email, "fullName": full_name},
            "otpCode": otp,
            "browserData": self._browser_data(
                page_name="EMAIL_VERIFICATION",
                event_type="EmailVerification")
        }
        r = self._profile_post("/api/create-identity", payload)
        if not r: return None
        reg_code = r.get("registrationCode")
        sign_in_state = r.get("signInState")
        if not reg_code or not sign_in_state:
            self.log(f"  ERROR missing registrationCode or signInState")
            return None
        self.log(f"  OK registrationCode: {reg_code[:40]}...")
        return r

    # ═══ Step 9: signup execute (registrationCode -> get-new-password) ═══
    def step9_signup_registration(self, reg_code, sign_in_state):
        self.log("Step 9: signup with registrationCode...")
        self._setup_signin_js_cookies()
        try: self.s.cookies.delete("awsccc", domain="us-east-1.signin.aws")
        except: pass
        awsccc = json.dumps({"e": 1, "p": 1, "f": 1, "a": 1, "i": _uuid(), "v": "1"},
                            separators=(",", ":"))
        self.s.cookies.set("awsccc",
                           base64.b64encode(awsccc.encode()).decode(),
                           domain="us-east-1.signin.aws", path="/")
        signup_url = (f"{SIGNIN}/platform/{DIR_ID}/signup"
                      f"?registrationCode={reg_code}"
                      f"&state={sign_in_state}")
        self.log(f"  9a: GET {signup_url[:100]}...")
        r = self.s.get(signup_url, headers={**self.ua, "accept": "text/html",
            "referer": f"{PROFILE}/"}, allow_redirects=True)
        self._capture_cookies(r)
        self.log(f"  Status: {r.status_code}")
        self.s.get(f"{SIGNIN}/assets/js/app.js",
                   headers={**self.ua, "accept": "*/*", "referer": signup_url})
        self.s.get(f"{SIGNIN}/assets/css/app.css",
                   headers={**self.ua, "accept": "text/css", "referer": signup_url})
        self.s.get(f"{SIGNIN}/platform/config?directoryId=",
                   headers={**self.ua, "accept": "*/*", "referer": signup_url})
        time.sleep(0.5)
        req_id = _uuid()
        fwcim = self._gen_signin_fwcim()
        fp_i = {"input_type": "FingerPrintRequestInput", "fingerPrint": fwcim}
        reg_i = {
            "input_type": "UserRegistrationRequestInput",
            "registrationCode": reg_code,
            "state": sign_in_state
        }
        self.log("  9b: POST signup/api/execute (registrationCode)...")
        url = f"{SIGNIN}/platform/{DIR_ID}/signup/api/execute"
        body = {
            "stepId": "",
            "state": sign_in_state,
            "inputs": [reg_i, fp_i],
            "requestId": req_id
        }
        h = {**self.ua, "accept": "application/json, text/plain, */*",
             "content-type": "application/json; charset=UTF-8",
             "origin": SIGNIN,
             "x-amzn-requestid": req_id,
             "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
             "referer": signup_url,
             "sec-fetch-site": "same-origin",
             "sec-fetch-mode": "cors",
             "sec-fetch-dest": "empty",
             "sec-gpc": "1",
             "priority": "u=1, i"}
        self.log(f"  POST {url}")
        r = self.s.post(url, headers=h, json=body)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if r.status_code != 200:
            self.log(f"  ERROR {r.status_code}: {r.text[:500]}")
            return None
        d = r.json()
        self.log(f"  -> sid={d.get('stepId')} wsh={d.get('workflowStateHandle', '')[:40]}")
        if d.get("stepId") != "get-new-password-for-password-creation":
            self.log(f"  ERROR expected get-new-password, got {d.get('stepId')}")
            return None
        self.log("  OK entered password setup step")
        self._signup_reg_url = signup_url
        return d

    # ═══ Step 10: set password (JWE encrypted) ═══
    def step10_set_password(self, pwd, email, step9_resp):
        self.log("Step 10: set password (JWE encrypted)...")
        wsh = step9_resp.get("workflowStateHandle", "")
        enc_ctx = (step9_resp.get("workflowResponseData", {})
                   .get("encryptionContextResponse", {}))
        pub_key = enc_ctx.get("publicKey")
        if not pub_key:
            self.log("  ERROR no public key, cannot encrypt password")
            return None
        self.log(f"  public key kid: {pub_key.get('kid')}")
        for c in list(self.s.cookies.jar):
            if c.domain and c.domain.startswith(".") and "signin.aws" in c.domain:
                try: self.s.cookies.delete(c.name, domain=c.domain, path=c.path)
                except: pass
        fwcim = self._gen_signin_fwcim()
        fp_i = {"input_type": "FingerPrintRequestInput", "fingerPrint": fwcim}
        evt_load = {
            "inputs": [
                {"input_type": "UserEventRequestInput",
                 "directoryId": DIR_ID,
                 "userName": email,
                 "userEvents": [{"input_type": "UserEvent",
                                 "eventType": "PAGE_LOAD",
                                 "pageName": "CREDENTIAL_COLLECTION"}]},
                fp_i
            ],
            "requestId": _uuid()
        }
        referer = getattr(self, '_signup_reg_url', f"{SIGNIN}/platform/{DIR_ID}/signup")
        se_h = {**self.ua, "accept": "application/json, text/plain, */*",
                "content-type": "application/json; charset=UTF-8",
                "origin": SIGNIN,
                "x-amzn-requestid": evt_load["requestId"],
                "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
                "referer": referer,
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty"}
        self.log("  10a: send-event (PAGE_LOAD CREDENTIAL_COLLECTION)...")
        self.s.post(f"{SIGNIN}/platform/user-event/send-event",
                    headers=se_h, json=evt_load)
        fwcim2 = self._gen_signin_fwcim()
        self.s.post(f"{SIGNIN}/metrics/fingerprint",
                    headers={**self.ua, "accept": "*/*",
                             "content-type": "application/x-www-form-urlencoded",
                             "origin": SIGNIN, "referer": referer},
                    data=f"name=IsFingerprintGenerated:Success&value={fwcim2}")
        time.sleep(random.uniform(1.0, 3.0))
        jwe_password = encrypt_password_jwe(pwd, pub_key)
        self.log(f"  OK JWE encrypted, len={len(jwe_password)}")
        req_id = _uuid()
        fwcim3 = self._gen_signin_fwcim(page_type="signup", event_type="PageSubmit", email=email)
        fp_i2 = {"input_type": "FingerPrintRequestInput", "fingerPrint": fwcim3}
        pwd_i = {
            "input_type": "PasswordRequestInput",
            "password": jwe_password,
            "successfullyEncrypted": "SUCCESSFUL",
            "errorLog": None
        }
        usr_i = {"input_type": "UserRequestInput", "username": email}
        evt_i = {
            "input_type": "UserEventRequestInput",
            "directoryId": DIR_ID,
            "userName": email,
            "userEvents": [{
                "input_type": "UserEvent",
                "eventType": "PAGE_SUBMIT",
                "pageName": "CREDENTIAL_COLLECTION",
                "timeSpentOnPage": random.randint(8000, 25000)
            }]
        }
        url = f"{SIGNIN}/platform/{DIR_ID}/signup/api/execute"
        body = {
            "stepId": "get-new-password-for-password-creation",
            "workflowStateHandle": wsh,
            "actionId": "SUBMIT",
            "inputs": [pwd_i, evt_i, usr_i, fp_i2],
            "visitorId": self._tes_visitor_id or "",
            "requestId": req_id
        }
        h = {**self.ua, "accept": "application/json, text/plain, */*",
             "content-type": "application/json; charset=UTF-8",
             "origin": SIGNIN,
             "x-amzn-requestid": req_id,
             "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
             "referer": referer,
             "sec-fetch-site": "same-origin",
             "sec-fetch-mode": "cors",
             "sec-fetch-dest": "empty",
             "sec-gpc": "1",
             "priority": "u=1, i"}
        cleanup_domains = [".us-east-1.signin.aws", ".signin.aws", "signin.aws"]
        cleaned = 0
        for c in list(self.s.cookies.jar):
            if c.domain in cleanup_domains:
                try:
                    self.s.cookies.delete(c.name, domain=c.domain, path=c.path)
                    cleaned += 1
                except: pass
        if cleaned:
            self.log(f"  cleaned {cleaned} non-bare-domain cookies")
        self.log(f"  10b: POST {url}")
        r = self.s.post(url, headers=h, json=body)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if r.status_code != 200:
            self.log(f"  ERROR {r.status_code}: {r.text[:500]}")
            return None
        d = r.json()
        self.log(f"  -> sid={d.get('stepId')}")
        if d.get("stepId") != "end-of-user-registration-success":
            self.log(f"  ERROR expected end-of-user-registration-success")
            return None
        redir_url = d.get("redirect", {}).get("url", "")
        if redir_url:
            m_wrh = re.search(r"workflowResultHandle=([^&#]+)", redir_url)
            if m_wrh:
                self._workflow_result_handle = m_wrh.group(1)
                self.log(f"  workflowResultHandle={self._workflow_result_handle}")
            # 提取 state 参数（用于 SSO token）
            m_state = re.search(r"[?&]state=([^&#]+)", redir_url)
            if m_state:
                self._sso_state = m_state.group(1)
                self.log(f"  sso_state={self._sso_state[:60]}...")
        self.log("  OK password set, registration complete!")
        return d

    # ═══ Step 11: final login ═══
    def step11_final_login(self, email, step10_resp):
        self.log("Step 11: final login...")
        redir = step10_resp.get("redirect", {}).get("url", "")
        if not redir:
            self.log("  ERROR no redirect URL")
            return None
        self.log(f"  redirect: {redir[:120]}...")
        p = urlparse(redir)
        qs = parse_qs(p.query)
        login_wsh = qs.get("workflowStateHandle", [None])[0]
        state = qs.get("state", [None])[0]
        wf_result = qs.get("workflowResultHandle", [None])[0]
        if not login_wsh or not state or not wf_result:
            self.log(f"  ERROR redirect params incomplete")
            return None
        fwcim = self._gen_signin_fwcim()
        fp_i = {"input_type": "FingerPrintRequestInput", "fingerPrint": fwcim}
        usr_i = {"input_type": "UserRequestInput", "username": email}
        url = f"{SIGNIN}/platform/{DIR_ID}/api/execute"
        body = {
            "stepId": "",
            "workflowStateHandle": login_wsh,
            "workflowResultHandle": wf_result,
            "state": state,
            "inputs": [usr_i, fp_i],
            "visitorId": self._tes_visitor_id or "",
            "requestId": _uuid()
        }
        h = {**self.ua, "accept": "application/json",
             "content-type": "application/json",
             "origin": SIGNIN,
             "referer": f"{SIGNIN}/platform/{DIR_ID}/login"}
        self.log(f"  POST {url}")
        r = self.s.post(url, headers=h, json=body)
        self.log(f"  Status: {r.status_code}")
        self._capture_cookies(r)
        if r.status_code != 200:
            self.log(f"  ERROR {r.status_code}: {r.text[:500]}")
            return None
        d = r.json()
        self.log(f"  -> sid={d.get('stepId')}")
        if d.get("stepId") == "end-of-workflow-success":
            self.log("  OK login success! workflow complete!")
            redir11 = d.get("redirect", {}).get("url", "")
            if redir11:
                self.log(f"  redirect URL: {redir11[:200]}...")
                p11 = urlparse(redir11)
                qs11 = parse_qs(p11.query)

                # 提取 code (这是真正的 auth_code)
                code = (qs11.get("code") or [None])[0]
                if code:
                    self._auth_code = code
                    self.log(f"  auth_code: {code[:60]}...")

                # 提取 state (用于 Kiro OAuth)
                s11 = qs11.get("state", [None])[0]
                if s11:
                    self._step11_state = s11
                    self.log(f"  kiro_state: {s11[:60]}...")

                # workflowResultHandle (如果有的话，更新；否则保留 step10 的值)
                wrh11 = qs11.get("workflowResultHandle", [None])[0]
                if wrh11:
                    self._workflow_result_handle = wrh11
                    self.log(f"  workflowResultHandle: {wrh11[:60]}...")

                # sso_state 保留 step10 的值，不从 step11 更新
        else:
            self.log(f"  WARNING stepId={d.get('stepId')}, may need extra steps")
        return d

    # ═══ Step 12: ExchangeToken (+ optional SSO for refreshToken) ═══
    def step12_get_tokens(self):
        """
        获取 Kiro tokens。
        流程：SSO 获取 refreshToken → Kiro Authorize 获取 code → ExchangeToken
        """
        self.log("Step 12: Get tokens...")

        PORTAL = "https://portal.sso.us-east-1.amazonaws.com"
        VIEW = "https://view.awsapps.com"
        OIDC = "https://oidc.us-east-1.amazonaws.com"

        # ═══ 12a: SSO + Device Auth → refreshToken ═══
        refresh_info = self._get_refresh_token_via_sso(PORTAL, VIEW, OIDC)
        refresh_token = refresh_info.get("refreshToken", "") if refresh_info else ""

        # ═══ 12b: Kiro Authorize → code → ExchangeToken ═══
        self.log("  12b: Kiro Authorize...")
        kiro_cv, kiro_cc = _pkce()
        kiro_state = _uuid()
        kvid = self.vid

        init_body = cbor2.dumps({
            "idp": "BuilderId",
            "redirectUri": f"{KIRO}/signin/oauth",
            "codeChallenge": kiro_cc,
            "codeChallengeMethod": "S256",
            "state": kiro_state,
        })
        init_h = {**self.ua, "accept": "application/cbor", "content-type": "application/cbor",
                  "smithy-protocol": "rpc-v2-cbor", "origin": KIRO,
                  "referer": f"{KIRO}/signin", "x-kiro-visitorid": kvid,
                  "amz-sdk-invocation-id": _uuid(), "amz-sdk-request": "attempt=1; max=1",
                  "x-amz-user-agent": "aws-sdk-js/1.0.0 ua/2.1 os/Windows#NT-10.0 lang/js md/browser#Google-Chrome_137.0.0.0 m/M,E",
                  "priority": "u=1, i"}
        r = self.s.post(f"{KIRO}/service/KiroWebPortalService/operation/InitiateLogin",
                        headers=init_h, data=init_body,
                        cookies={"kiro-visitor-id": kvid})
        if r.status_code != 200:
            self.log(f"  ERROR InitiateLogin failed: {r.status_code}")
            return None
        rd = cbor2.loads(r.content)
        auth_url = rd.get("redirectUrl", "")
        if not auth_url:
            self.log(f"  ERROR no redirectUrl")
            return None

        pq = parse_qs(urlparse(auth_url).query)
        if pq.get("state"):
            kiro_state = pq["state"][0]

        # GET /authorize → 302 chain → 最终拿到 code
        self.log("  12b-1: GET /authorize...")
        r = self.s.get(auth_url, headers={
            **self.ua, "accept": "text/html,*/*;q=0.8",
            "referer": f"{KIRO}/",
            "sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site", "upgrade-insecure-requests": "1",
        }, allow_redirects=False)

        loc = r.headers.get("location", "")
        self._capture_cookies(r)
        if not loc:
            self.log(f"  authorize returned {r.status_code}, no redirect")
            return None

        self.log(f"  authorize 302 → {loc[:100]}...")

        # Follow redirect chain 直到拿到 code
        max_redirects = 8
        kiro_code = None
        while loc and max_redirects > 0:
            # 检查是否已经拿到 code
            pq = parse_qs(urlparse(loc).query)
            if pq.get("code"):
                kiro_code = pq["code"][0]
                if pq.get("state"):
                    kiro_state = pq["state"][0]
                self.log(f"  Got code: {kiro_code[:40]}...")
                break

            # 继续 follow
            full_url = loc if loc.startswith("http") else f"{SIGNIN}{loc}"
            r = self.s.get(full_url, headers={
                **self.ua, "accept": "text/html,*/*;q=0.8",
                "sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
            }, allow_redirects=False)
            self._capture_cookies(r)

            if r.status_code == 302:
                loc = r.headers.get("location", "")
                self.log(f"  follow → {loc[:100]}...")
            elif r.status_code == 200:
                # 可能需要执行 signin 工作流
                wsh_match = pq.get("workflowStateHandle", [None])
                if wsh_match and wsh_match[0]:
                    self.log(f"  执行 signin 工作流...")
                    fp_i = {"input_type": "FingerPrintRequestInput", "fingerPrint": self._gen_signin_fwcim(page_type="signin")}
                    api = f"{SIGNIN}/platform/{DIR_ID}/api/execute"
                    rid = _uuid()
                    h = {**self.ua, "accept": "application/json, text/plain, */*",
                         "content-type": "application/json", "origin": SIGNIN,
                         "referer": full_url, "x-amzn-requestid": rid,
                         "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
                         "priority": "u=1, i"}
                    # stepId=""
                    resp = self.s.post(api, headers=h, json={
                        "stepId": "", "workflowStateHandle": wsh_match[0],
                        "inputs": [fp_i], "requestId": rid})
                    self._capture_cookies(resp)
                    if resp.status_code == 200:
                        data = resp.json()
                        new_wsh = data.get("workflowStateHandle", wsh_match[0])
                        if data.get("stepId") == "start":
                            rid = _uuid()
                            h["x-amzn-requestid"] = rid
                            resp = self.s.post(api, headers=h, json={
                                "stepId": "start", "workflowStateHandle": new_wsh,
                                "inputs": [fp_i], "requestId": rid})
                            self._capture_cookies(resp)
                            if resp.status_code == 200:
                                data = resp.json()
                        if data.get("stepId") == "end-of-workflow-success":
                            redir = data.get("redirect", {}).get("url", "")
                            if redir:
                                loc = redir
                                self.log(f"  工作流完成 → {loc[:100]}...")
                                continue
                break
            else:
                break
            max_redirects -= 1

        if not kiro_code:
            self.log("  ERROR: Failed to get kiro code")
            return None

        # ExchangeToken
        return self._exchange_token(kiro_code, kiro_cv, kiro_state,
                                    refresh_token=refresh_token,
                                    client_id=self._device_client_id or "",
                                    client_secret=self._device_client_secret or "")

    def get_stripe_link(self, access_token: str, csrf_token: str) -> str:
        """用当前 session 获取 Stripe 支付链接（session 已有 cookies）"""
        self.log("  Getting Stripe Pro link...")
        PROFILE_ARN = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX"

        payload = cbor2.dumps({
            "subscriptionType": "Q_DEVELOPER_STANDALONE_PRO",
            "profileArn": PROFILE_ARN,
        })
        headers = {
            **self.ua,
            "accept": "application/cbor",
            "content-type": "application/cbor",
            "smithy-protocol": "rpc-v2-cbor",
            "authorization": f"Bearer {access_token}",
            "x-csrf-token": csrf_token,
            "x-kiro-visitorid": self.vid,
            "x-amz-user-agent": "aws-sdk-js/1.0.0 ua/2.1 os/macOS lang/js md/browser#Chromium_147 m/N,M,E",
            "amz-sdk-invocation-id": _uuid(),
            "amz-sdk-request": "attempt=1; max=1",
            "origin": KIRO,
            "referer": f"{KIRO}/account/usage",
            "priority": "u=1, i",
        }
        # 添加 x-kiro-userid（从 ExchangeToken 的 set-cookie 中获取）
        if hasattr(self, '_kiro_user_id') and self._kiro_user_id:
            headers["x-kiro-userid"] = self._kiro_user_id
        try:
            r = self.s.post(
                f"{KIRO}/service/KiroWebPortalService/operation/GenerateSubscriptionManagementUrl",
                headers=headers, data=payload)
            if r.status_code == 200:
                data = cbor2.loads(r.content)
                if isinstance(data, dict):
                    url = data.get("encodedVerificationUrl", "")
                    if url:
                        self.log(f"  OK Stripe URL: {url[:80]}...")
                        return url
                # Fallback: 从二进制提取
                import re as _re
                text = r.content.decode("latin-1")
                m = _re.search(r'https://(?:checkout|billing)\.stripe\.com/[A-Za-z0-9_/#%&=.+\-?]+', text)
                if m:
                    return m.group(0)
            else:
                self.log(f"  Stripe link failed: HTTP {r.status_code}")
                try:
                    err = cbor2.loads(r.content)
                    self.log(f"  {err}")
                except:
                    pass
        except Exception as e:
            self.log(f"  Stripe link error: {e}")
        return ""

    def _get_refresh_token_via_sso(self, PORTAL, VIEW, OIDC):
        """通过 SSO + device auth 获取 refreshToken"""
        self.log("  Getting refreshToken via SSO...")
        # 获取 loginCsrfToken — 用 s_plain 避免 TLS 问题
        redirect_url = url_quote(f"{VIEW}/start/#/", safe="")
        login_url = f"{PORTAL}/login?directory_id=view&redirect_url={redirect_url}"
        login_h = {**self.ua, "accept": "*/*", "content-type": "application/json",
                   "origin": VIEW, "referer": f"{VIEW}/",
                   "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors",
                   "sec-fetch-dest": "empty"}
        try:
            r = self.s_plain.get(login_url, headers=login_h, timeout=30)
        except Exception as e:
            self.log(f"  portal login failed: {e}")
            return None
        if r.status_code != 200:
            return None
        data = r.json()
        login_csrf_token = data.get("csrfToken")
        if not login_csrf_token:
            return None
        redir_url = data.get("redirectUrl", "")
        new_wsh = None
        if "workflowStateHandle=" in redir_url:
            new_wsh = redir_url.split("workflowStateHandle=")[1].split("&")[0]
        if not new_wsh:
            return None

        # 完成 SSO 工作流
        sso_api = f"{SIGNIN}/platform/{DIR_ID}/api/execute"
        fp_i = {"input_type": "FingerPrintRequestInput", "fingerPrint": self._gen_signin_fwcim(page_type="signin")}
        rid = _uuid()
        sso_h = {**self.ua, "accept": "application/json, text/plain, */*",
                 "content-type": "application/json", "origin": SIGNIN,
                 "referer": f"{SIGNIN}/platform/{DIR_ID}/login?workflowStateHandle={new_wsh}",
                 "x-amzn-requestid": rid,
                 "x-amz-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
                 "priority": "u=1, i"}
        r = self.s.post(sso_api, headers=sso_h, json={
            "stepId": "", "workflowStateHandle": new_wsh, "inputs": [fp_i], "requestId": rid})
        self._capture_cookies(r)
        if r.status_code == 200:
            sso_data = r.json()
            new_wsh = sso_data.get("workflowStateHandle", new_wsh)
            if sso_data.get("stepId") == "start":
                rid = _uuid()
                sso_h["x-amzn-requestid"] = rid
                r = self.s.post(sso_api, headers=sso_h, json={
                    "stepId": "start", "workflowStateHandle": new_wsh, "inputs": [fp_i], "requestId": rid})
                self._capture_cookies(r)
                if r.status_code == 200:
                    sso_data = r.json()
            if sso_data.get("stepId") == "end-of-workflow-success":
                final_redir = sso_data.get("redirect", {}).get("url", "")
                if final_redir:
                    qs = parse_qs(urlparse(final_redir).query)
                    self._workflow_result_handle = (qs.get("workflowResultHandle") or [self._workflow_result_handle])[0]
                    self._sso_state = (qs.get("state") or [self._sso_state])[0]

        # 获取 SSO token
        sso_body = urlencode({"authCode": self._workflow_result_handle or "", "state": self._sso_state or "", "orgId": "view"})
        sso_token_h = {**self.ua, "accept": "application/json, text/plain, */*",
                       "content-type": "application/x-www-form-urlencoded",
                       "x-amz-sso-csrf-token": str(login_csrf_token),
                       "origin": VIEW, "referer": f"{VIEW}/",
                       "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty"}
        sso_token = None
        for retry in range(5):
            r = self.s_plain.post(f"{PORTAL}/auth/sso-token", headers=sso_token_h, data=sso_body)
            if r.status_code == 200:
                sso_token = r.json().get("token")
                if sso_token:
                    break
            time.sleep(2)
        if not sso_token:
            self.log("  SSO token failed")
            return None

        # Device auth
        oidc_h = {**self.ua, "accept": "application/json, text/plain, */*",
                  "content-type": "application/json", "origin": VIEW, "referer": f"{VIEW}/",
                  "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty"}
        r = self.s_plain.post(f"{OIDC}/device_authorization/accept_user_code",
                        headers=oidc_h, json={"userCode": self._user_code, "userSessionId": sso_token})
        if r.status_code != 200:
            self.log(f"  accept_user_code failed: {r.status_code}")
            return None
        dc = r.json().get("deviceContext", {})
        self.s_plain.post(f"{OIDC}/device_authorization/associate_token",
                    headers=oidc_h, json={"deviceContext": dc, "userSessionId": sso_token})

        # Poll token
        token_h = {"content-type": "application/json",
                   "user-agent": "aws-sdk-rust/1.3.9 os/windows lang/rust/1.87.0",
                   "amz-sdk-request": "attempt=1; max=3", "amz-sdk-invocation-id": _uuid()}
        token_body = {"clientId": self._device_client_id, "clientSecret": self._device_client_secret,
                      "deviceCode": self._device_code, "grantType": "urn:ietf:params:oauth:grant-type:device_code"}
        for i in range(30):
            r = self.s_plain.post(f"{OIDC}/token", headers=token_h, json=token_body)
            if r.status_code == 200:
                oidc_token = r.json()
                self.log(f"  OK refreshToken obtained")
                return {"clientId": self._device_client_id, "clientSecret": self._device_client_secret,
                        "refreshToken": oidc_token.get("refreshToken", "")}
            time.sleep(2)
        self.log("  refreshToken poll timeout")
        return None

    # ═══ 以下是旧的完整 SSO + Kiro Authorize 流程（已注释，保留备用） ═══
    # def _full_sso_token_flow(self, PORTAL, VIEW, OIDC):
    #     """完整的 SSO + device auth + Kiro authorize + ExchangeToken"""
    #     ... (see git history for full implementation)

    def _exchange_token(self, code, code_verifier, state,
                        refresh_token="", client_id="", client_secret=""):
        """调用 Kiro ExchangeToken API"""
        self.log("  ExchangeToken...")
        kvid = self.vid
        exchange_body = cbor2.dumps({
            "idp": "BuilderId",
            "code": code,
            "codeVerifier": code_verifier,
            "redirectUri": f"{KIRO}/signin/oauth",
            "state": state,
        })
        exchange_h = {**self.ua, "accept": "application/cbor",
            "content-type": "application/cbor", "smithy-protocol": "rpc-v2-cbor",
            "origin": KIRO,
            "referer": f"{KIRO}/signin/oauth?code={code}&state={state}",
            "x-kiro-visitorid": kvid,
            "amz-sdk-invocation-id": _uuid(), "amz-sdk-request": "attempt=1; max=1",
            "x-amz-user-agent": "aws-sdk-js/1.0.0 ua/2.1 os/Windows#NT-10.0 lang/js md/browser#Google-Chrome_137.0.0.0 m/M,E",
            "priority": "u=1, i"}
        r = self.s.post(
            f"{KIRO}/service/KiroWebPortalService/operation/ExchangeToken",
            headers=exchange_h, data=exchange_body,
            cookies={"kiro-visitor-id": kvid})
        self._capture_cookies(r)
        self.log(f"  ExchangeToken Status: {r.status_code}")
        if r.status_code != 200:
            self.log(f"  ERROR ExchangeToken failed: {r.status_code}")
            try:
                err_data = cbor2.loads(r.content)
                self.log(f"  Error details: {err_data}")
            except:
                self.log(f"  Response: {r.text[:500]}")
            return None
        try:
            resp_data = cbor2.loads(r.content)
        except Exception as e:
            self.log(f"  ERROR CBOR parse failed: {e}")
            return None

        access_token = resp_data.get("accessToken", "")
        kiro_csrf = resp_data.get("csrfToken", "")
        expires_in = resp_data.get("expiresIn", 0)
        if not access_token:
            self.log(f"  ERROR no accessToken: {resp_data}")
            return None
        self.log(f"  OK accessToken={access_token[:60]}...")

        # 从 set-cookie 中提取 UserId 供后续请求使用
        self._kiro_user_id = ""
        try:
            # curl_requests cookies 可能是 dict-like
            for name, value in self.s.cookies.items():
                if name == "UserId":
                    self._kiro_user_id = value
                    break
        except:
            pass
        if not self._kiro_user_id:
            # 从响应 headers 直接提取
            for k, v in r.headers.multi_items():
                if k.lower() == "set-cookie" and "UserId=" in v:
                    import re as _re
                    m = _re.search(r"UserId=([^;]+)", v)
                    if m:
                        self._kiro_user_id = m.group(1)
                        break

        return {
            "accessToken": access_token,
            "csrfToken": kiro_csrf,
            "expiresIn": expires_in,
            "refreshToken": refresh_token,
            "clientId": client_id,
            "clientSecret": client_secret,
        }

    # ═══ Full registration flow ═══
    def register(self, email, pwd=None, name="Kiro User",
                 otp_timeout=120, otp_callback=None):
        """
        Execute full Kiro registration flow.

        Args:
            email: Email address for registration
            pwd: Password (auto-generated if None)
            name: Display name
            otp_timeout: Max seconds to wait for OTP
            otp_callback: Callable that returns the OTP code string.
                          If None, user will be prompted for manual input.

        Returns:
            (ok: bool, info: dict)
        """
        if not pwd:
            pwd = _pwd()
            self.log(f"  auto-generated password: {pwd}")
        self.log(f"========== Register: {email} ==========")

        # Step 0: 预先注册 OIDC client 和 device authorization
        if not self.step0_init_device_auth():
            return False, {"error": "Device auth initialization failed"}

        redir = self.step1_kiro_init()
        if not redir: return False, {"error": "InitiateLogin failed"}
        if not self.step2_get_wsh(redir):
            return False, {"error": "Failed to get wsh"}
        if not self.step3_signin_flow(email):
            return False, {"error": "signin flow failed"}
        if not self.step4_signup_flow(email):
            return False, {"error": "signup flow failed"}
        if not self.profile_wf_id:
            return False, {"error": "No workflowID"}
        tes = self.step5_get_tes_token()
        if not tes: self.log("  WARNING TES token failed, continuing...")
        r6 = self.step6_profile_load()
        if not r6: return False, {"error": "profile start failed"}
        r7 = self.step7_send_otp(email)
        if r7 is None: return False, {"error": "send OTP failed"}

        if otp_callback:
            self.log("  auto-fetching OTP...")
            otp = otp_callback()
        else:
            otp = input(f"[{self.tag}] Enter OTP code: ").strip()
        if not otp: return False, {"error": "No OTP received"}

        r8 = self.step8_create_identity(otp, email, name)
        if not r8: return False, {"error": "create-identity failed"}
        reg_code = r8["registrationCode"]
        sign_in_state = r8["signInState"]
        r9 = self.step9_signup_registration(reg_code, sign_in_state)
        if not r9: return False, {"error": "signup registration failed"}
        r10 = self.step10_set_password(pwd, email, r9)
        if not r10: return False, {"error": "set password failed"}
        r11 = self.step11_final_login(email, r10)
        if not r11: self.log("  WARNING final login failed, but account may exist")

        # Step 12: 完整的 SSO + Kiro Authorize + ExchangeToken 流程
        # 现在 step12 内部已经包含了 device auth 和 Kiro authorize
        time.sleep(2)  # SSO 同步等待
        tokens = self.step12_get_tokens()
        if tokens:
            self.log("Registration complete! (accessToken + refreshToken)")
            return True, {
                "email": email, "password": pwd, "name": name,
                "accessToken": tokens.get("accessToken", ""),
                "csrfToken": tokens.get("csrfToken", ""),
                "expiresIn": tokens.get("expiresIn", 0),
                "refreshToken": tokens.get("refreshToken", ""),
                "clientId": tokens.get("clientId", ""),
                "clientSecret": tokens.get("clientSecret", ""),
            }
        else:
            self.log("Registration failed: token fetch failed")
            return False, {"error": "token fetch failed"}
