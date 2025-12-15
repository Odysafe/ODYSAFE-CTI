"""
Odysafe CTI Platform
Copyright (C) 2025 Bastien GUIDONE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Download lock mechanism to prevent simultaneous Git repository downloads
"""
import fcntl
import logging
import os
import time
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

# Lock file directory
LOCK_DIR = Path(__file__).parent / "cache"
LOCK_DIR.mkdir(exist_ok=True)
GLOBAL_DOWNLOAD_LOCK_FILE = LOCK_DIR / "git_download.lock"


@contextmanager
def download_lock(lock_name: str = "global", timeout: int = 300):
    """
    Context manager for download locks to prevent simultaneous Git operations.
    
    Args:
        lock_name: Name of the lock (for different repositories)
        timeout: Maximum time to wait for lock (seconds)
    
    Yields:
        bool: True if lock acquired, False if timeout
    
    Raises:
        RuntimeError: If lock cannot be acquired within timeout
    """
    lock_file = LOCK_DIR / f"{lock_name}_download.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    
    lock_fd = None
    lock_acquired = False
    
    try:
        # Try to acquire lock
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                lock_fd = open(lock_file, 'w')
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_acquired = True
                # Write PID to lock file for debugging
                lock_fd.write(str(os.getpid()))
                lock_fd.flush()
                logger.debug(f"Download lock acquired: {lock_name}")
                break
            except (IOError, OSError) as e:
                if lock_fd:
                    lock_fd.close()
                    lock_fd = None
                # Lock is held by another process
                wait_time = min(2, timeout - (time.time() - start_time))
                if wait_time > 0:
                    time.sleep(wait_time)
                else:
                    break
        
        if not lock_acquired:
            raise RuntimeError(
                f"Could not acquire download lock '{lock_name}' within {timeout} seconds. "
                "Another download operation may be in progress."
            )
        
        yield True
        
    finally:
        # Release lock
        if lock_fd:
            try:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                lock_fd.close()
            except Exception as e:
                logger.warning(f"Error releasing lock: {e}")
            
            # Remove lock file
            try:
                if lock_file.exists():
                    lock_file.unlink()
            except Exception as e:
                logger.warning(f"Error removing lock file: {e}")
            
            logger.debug(f"Download lock released: {lock_name}")
