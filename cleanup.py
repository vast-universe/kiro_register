"""
清理 kiro_accounts.txt — 移除已完成或无效的账号

已清理的账号会被移到 kiro_accounts_done.txt 存档，不会丢失。

用法:
    python cleanup.py              # 清理已完成账号（paid + overage）
    python cleanup.py --dry-run    # 只预览，不实际操作
    python cleanup.py --all-paid   # 清理所有已支付账号（不管超额是否开启）
    python cleanup.py --invalid    # 清理缺少支付链接或 refreshToken 的无效账号
"""

import os
import json
import argparse
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KIRO_ACCOUNTS_FILE = os.path.join(BASE_DIR, "kiro_accounts.txt")
DONE_FILE = os.path.join(BASE_DIR, "kiro_accounts_done.txt")


def main():
    parser = argparse.ArgumentParser(description="Cleanup completed accounts")
    parser.add_argument("--dry-run", action="store_true", help="Preview only, don't modify files")
    parser.add_argument("--all-paid", action="store_true", help="Remove all paid accounts (not just overage-enabled)")
    parser.add_argument("--invalid", action="store_true", help="Remove accounts missing stripeUrl or refreshToken")
    args = parser.parse_args()

    if not os.path.exists(KIRO_ACCOUNTS_FILE):
        print("ERROR: kiro_accounts.txt not found")
        return

    with open(KIRO_ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
        accounts = json.load(f)

    if not accounts:
        print("No accounts found.")
        return

    # 分类
    if args.invalid:
        done = [acc for acc in accounts
                if not acc.get("stripeUrl") or not acc.get("refreshToken")]
        keep = [acc for acc in accounts
                if acc.get("stripeUrl") and acc.get("refreshToken")]
        label = "missing stripeUrl or refreshToken"
    elif args.all_paid:
        done = [acc for acc in accounts if acc.get("paid")]
        keep = [acc for acc in accounts if not acc.get("paid")]
        label = "paid"
    else:
        done = [acc for acc in accounts if acc.get("paid") and acc.get("overage")]
        keep = [acc for acc in accounts if not (acc.get("paid") and acc.get("overage"))]
        label = "paid + overage"

    print(f"Total accounts: {len(accounts)}")
    print(f"Completed ({label}): {len(done)}")
    print(f"Remaining: {len(keep)}")

    if not done:
        print("\nNothing to clean up.")
        return

    # 预览
    print(f"\nAccounts to archive:")
    for i, acc in enumerate(done[:10]):
        print(f"  {i+1}. {acc.get('email')}")
    if len(done) > 10:
        print(f"  ... and {len(done) - 10} more")

    if args.dry_run:
        print("\n[DRY RUN] No changes made.")
        return

    # 存档到 done 文件
    existing_done = []
    if os.path.exists(DONE_FILE):
        try:
            with open(DONE_FILE, 'r', encoding='utf-8') as f:
                existing_done = json.load(f)
        except:
            existing_done = []

    # 添加清理时间戳
    for acc in done:
        acc["archivedAt"] = time.strftime("%Y-%m-%d %H:%M:%S")

    existing_done.extend(done)
    with open(DONE_FILE, 'w', encoding='utf-8') as f:
        json.dump(existing_done, f, indent=2, ensure_ascii=False)

    # 更新主文件
    with open(KIRO_ACCOUNTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(keep, f, indent=2, ensure_ascii=False)

    print(f"\n✓ Archived {len(done)} accounts to kiro_accounts_done.txt")
    print(f"✓ Remaining in kiro_accounts.txt: {len(keep)}")


if __name__ == "__main__":
    main()
