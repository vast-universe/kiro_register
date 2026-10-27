"""
跨平台文件锁实现
支持 Unix (fcntl) 和 Windows (msvcrt)
"""
import os
import sys
import time
from contextlib import contextmanager


class FileLock:
    """跨平台文件锁"""

    def __init__(self, file_path, timeout=30):
        """
        Args:
            file_path: 要锁定的文件路径
            timeout: 获取锁的超时时间（秒）
        """
        self.file_path = file_path
        self.timeout = timeout
        self.lock_file_path = f"{file_path}.lock"
        self.lock_file = None

    def acquire(self):
        """获取文件锁"""
        start_time = time.time()

        while True:
            try:
                # 创建锁文件（如果不存在）
                self.lock_file = open(self.lock_file_path, 'w')

                # 根据平台选择锁定方式
                if sys.platform == 'win32':
                    self._lock_windows()
                else:
                    self._lock_unix()

                return True
            except (IOError, OSError) as e:
                if self.lock_file:
                    self.lock_file.close()
                    self.lock_file = None

                # 检查超时
                if time.time() - start_time >= self.timeout:
                    raise TimeoutError(f"Failed to acquire lock for {self.file_path} after {self.timeout}s")

                # 等待后重试
                time.sleep(0.1)

    def release(self):
        """释放文件锁"""
        if self.lock_file:
            try:
                # 根据平台选择解锁方式
                if sys.platform == 'win32':
                    self._unlock_windows()
                else:
                    self._unlock_unix()
            finally:
                self.lock_file.close()
                self.lock_file = None

                # 删除锁文件
                try:
                    os.remove(self.lock_file_path)
                except OSError:
                    pass

    def _lock_unix(self):
        """Unix 系统使用 fcntl 锁定"""
        import fcntl
        fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_unix(self):
        """Unix 系统使用 fcntl 解锁"""
        import fcntl
        fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)

    def _lock_windows(self):
        """Windows 系统使用 msvcrt 锁定"""
        import msvcrt
        msvcrt.locking(self.lock_file.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock_windows(self):
        """Windows 系统使用 msvcrt 解锁"""
        import msvcrt
        msvcrt.locking(self.lock_file.fileno(), msvcrt.LK_UNLCK, 1)

    def __enter__(self):
        """上下文管理器入口"""
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出"""
        self.release()
        return False


@contextmanager
def file_lock(file_path, timeout=30):
    """
    文件锁上下文管理器

    Usage:
        with file_lock("data.txt"):
            # 在这里安全地读写文件
            pass
    """
    lock = FileLock(file_path, timeout)
    lock.acquire()
    try:
        yield lock
    finally:
        lock.release()
