"""
开启 Kiro Pro Overage（超额使用）

支付完成后运行此脚本，为账号开启超额使用功能。
开启后 credit 用完可继续使用（按量计费）。

用法:
    python enable_overage.py                # 为 kiro_accounts.txt 中所有账号开启
    python enable_overage.py --index 1      # 为第 1 个账号开启
    python enable_overage.py --token xxx    # 直接用 token 开启
"""

import os
import json
import uuid
import argparse
import requests

PROFILE_ARN = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX"
API_URL = "https://q.us-east-1.amazonaws.com/setUserPreference"

KIRO_VERSION = "0.12.200"
KIRO_BUILD_HASH = "e02f7bb38114ceef68bfabb92f43946b58cf124ef1331c245a88de8d80c4fbb0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KIRO_ACCOUNTS_FILE = os.path.join(BASE_DIR, "kiro_accounts.txt")


def enable_overage(access_token: str) -> bool:
    """
    开启 overage

    Args:
        access_token: Bearer token

    Returns:
        是否成功
    """
    headers = {
        "content-type": "application/json",
        "user-agent": f"aws-sdk-js/1.0.0 ua/2.1 os/darwin#24.6.0 lang/js md/nodejs#22.22.0 api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{KIRO_VERSION}-{KIRO_BUILD_HASH}",
        "x-amz-user-agent": f"aws-sdk-js/1.0.0 KiroIDE-{KIRO_VERSION}-{KIRO_BUILD_HASH}",
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1; max=1",
        "Authorization": f"Bearer {access_token}",
    }

    body = {
        "overageConfiguration": {
            "overageStatus": "ENABLED"
        },
        "profileArn": PROFILE_ARN,
    }

    try:
        r = requests.post(API_URL, headers=headers, json=body, timeout=30)
        if r.status_code == 200:
            return True
        else:
            print(f"  ERROR: HTTP {r.status_code} — {r.text[:200]}")
            return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def refresh_and_enable(acc: dict) -> tuple:
    """
    刷新 token 后开启 overage
    
    Args:
        acc: 账号字典（需要 refreshToken, clientId, clientSecret）
    
    Returns:
        (success: bool, new_access_token: str or None)
    """
    from switch import refresh_kiro_token

    rt = acc.get("refreshToken", "")
    cid = acc.get("clientId", "")
    cs = acc.get("clientSecret", "")

    if not rt or not cid or not cs:
        # 没有 refresh 信息，直接用已有的 accessToken 试试
        at = acc.get("accessToken", "")
        if at:
            return enable_overage(at), None
        return False, None

    # 刷新 token
    ok, result = refresh_kiro_token(rt, cid, cs)
    if not ok:
        print(f"  token refresh failed: {result.get('error', '')}")
        return False, None

    new_at = result["accessToken"]
    # 用新 token 开启 overage
    success = enable_overage(new_at)
    return success, new_at if success else None
    parser = argparse.ArgumentParser(description="Enable Kiro Pro Overage")
    parser.add_argument("--index", type=int, help="Account index (1-based)")
    parser.add_argument("--token", type=str, help="Access token (direct)")
    args = parser.parse_args()

    if args.token:
        print("Enabling overage...")
        if enable_overage(args.token):
            print("✓ Overage enabled")
        else:
            print("✗ Failed")
        return

    if not os.path.exists(KIRO_ACCOUNTS_FILE):
        print(f"ERROR: {KIRO_ACCOUNTS_FILE} not found")
        return

    with open(KIRO_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
        accounts = json.load(f)

    if not accounts:
        print("No accounts found")
        return

    targets = [accounts[args.index - 1]] if args.index else accounts

    # 只处理已支付的账号（除非指定了 --index）
    if not args.index:
        paid_targets = [acc for acc in targets if acc.get("paid")]
        if paid_targets:
            targets = paid_targets
            print(f"Enabling overage for {len(targets)} paid account(s)...\n")
        else:
            print(f"Enabling overage for {len(targets)} account(s) (no paid filter)...\n")
    else:
        print(f"Enabling overage for account {args.index}...\n")

    success = 0
    for i, acc in enumerate(targets):
        email = acc.get("email", "unknown")
        print(f"[{i+1}] {email}...", end=" ")
        ok, new_token = refresh_and_enable(acc)
        if ok:
            print("✓")
            if new_token:
                acc["accessToken"] = new_token
            success += 1
        else:
            print("✗")

    # 保存更新后的 token
    with open(KIRO_ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2, ensure_ascii=False)

    print(f"\nDone: {success}/{len(targets)} enabled")


if __name__ == "__main__":
    main()
