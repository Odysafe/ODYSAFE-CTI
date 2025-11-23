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

Progress tracking system for sources and exports
"""
import threading
import time
import logging
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Manages progress tracking for running tasks"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ProgressTracker, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._progress: Dict[str, Dict] = {}
        self._stop_flags: Dict[str, threading.Event] = {}  # Flags to stop processes
        self._lock = threading.Lock()
        self._initialized = True
    
    def start_task(self, task_id: str, task_type: str, total_steps: int = 100):
        """
        Starts tracking a task
        
        Args:
            task_id: Unique task identifier
            task_type: Task type ('source_processing', 'export_generation', etc.)
            total_steps: Total number of steps (default 100)
        """
        with self._lock:
            self._progress[task_id] = {
                'type': task_type,
                'current_step': 0,
                'total_steps': total_steps,
                'percentage': 0,
                'status': 'running',
                'message': 'Starting...',
                'started_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            # Create an event for stopping
            self._stop_flags[task_id] = threading.Event()
        logger.info(f"Task {task_id} ({task_type}) started")
    
    def update_progress(self, task_id: str, current_step: int = None, 
                       percentage: int = None, message: str = None):
        """
        Updates the progress of a task
        
        Args:
            task_id: Task identifier
            current_step: Current step (optional)
            percentage: Percentage (0-100, optional)
            message: Status message (optional)
        """
        with self._lock:
            if task_id not in self._progress:
                logger.warning(f"Task {task_id} not found for update")
                return
            
            progress = self._progress[task_id]
            
            if current_step is not None:
                progress['current_step'] = current_step
                # Calculate percentage if not provided
                if percentage is None:
                    total = progress['total_steps']
                    progress['percentage'] = min(100, int((current_step / total) * 100)) if total > 0 else 0
            elif percentage is not None:
                progress['percentage'] = min(100, max(0, percentage))
                # Update current_step if possible
                total = progress['total_steps']
                if total > 0:
                    progress['current_step'] = int((percentage / 100) * total)
            
            if message:
                progress['message'] = message
            
            progress['updated_at'] = datetime.now().isoformat()
    
    def complete_task(self, task_id: str, message: str = "Completed"):
        """Marks a task as completed"""
        with self._lock:
            if task_id not in self._progress:
                return
            
            self._progress[task_id].update({
                'status': 'completed',
                'percentage': 100,
                'current_step': self._progress[task_id]['total_steps'],
                'message': message,
                'completed_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            })
        logger.info(f"Task {task_id} completed")
    
    def error_task(self, task_id: str, error_message: str):
        """Marks a task as failed"""
        with self._lock:
            if task_id not in self._progress:
                return
            
            self._progress[task_id].update({
                'status': 'error',
                'message': error_message,
                'updated_at': datetime.now().isoformat()
            })
        logger.error(f"Task {task_id} failed: {error_message}")
    
    def get_progress(self, task_id: str) -> Optional[Dict]:
        """Gets the progress of a task"""
        with self._lock:
            return self._progress.get(task_id, None)
    
    def stop_task(self, task_id: str):
        """Requests to stop a running task"""
        with self._lock:
            if task_id in self._stop_flags:
                self._stop_flags[task_id].set()
                if task_id in self._progress:
                    self._progress[task_id]['status'] = 'stopping'
                    self._progress[task_id]['message'] = 'Stopping...'
                logger.info(f"Stop requested for task {task_id}")
                return True
        return False
    
    def is_stopped(self, task_id: str) -> bool:
        """Checks if a task should be stopped"""
        with self._lock:
            if task_id in self._stop_flags:
                return self._stop_flags[task_id].is_set()
        return False
    
    def remove_task(self, task_id: str):
        """Removes a task from tracking (after a certain delay)"""
        with self._lock:
            if task_id in self._progress:
                del self._progress[task_id]
            if task_id in self._stop_flags:
                del self._stop_flags[task_id]


# Global instance
progress_tracker = ProgressTracker()

