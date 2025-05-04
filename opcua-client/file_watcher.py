# Improvements needed in file_watcher.py

import os
from PyQt5.QtCore import QObject, pyqtSignal, QFileSystemWatcher, QTimer

from utils import get_logger

logger = get_logger("file_watcher")


class FileWatcher(QObject):
    """File system watcher for custom nodes with improved monitoring"""
    
    file_changed = pyqtSignal(str)  # filepath
    
    def __init__(self, directory: str, parent=None):
        super().__init__(parent)
        self.directory = directory
        
        # Watch both the directory and files
        self.watcher = QFileSystemWatcher([], self)
        self.watcher.directoryChanged.connect(self.on_directory_changed)
        self.watcher.fileChanged.connect(self.on_file_changed)
        
        self.last_modification_times = {}
        self.pending_changes = {}  # filepath -> timer
        self.file_contents = {}  # Store file content hashes
        
        # Add the directory to watcher
        self._setup_directory_watching()
        
        # Periodic scan timer
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.periodic_scan)
        self.scan_timer.start(1000)  # Scan every second
        
        logger.debug(f"FileWatcher initialized for directory: {directory}")
    
    def _setup_directory_watching(self):
        """Setup watching for directory and existing files"""
        if os.path.exists(self.directory):
            self.watcher.addPath(self.directory)
            
            # Also watch individual files
            for filename in os.listdir(self.directory):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.directory, filename)
                    self._add_file_to_watch(filepath)
    
    def _add_file_to_watch(self, filepath: str):
        """Add a file to watch list"""
        try:
            # Add file to watcher
            if filepath not in self.watcher.files():
                self.watcher.addPath(filepath)
            
            # Store modification time and content hash
            self.last_modification_times[filepath] = os.path.getmtime(filepath)
            
            # Store content hash for change detection
            with open(filepath, 'r') as f:
                content = f.read()
                self.file_contents[filepath] = hash(content)
            
            logger.debug(f"Added file to watch: {filepath}")
        except Exception as e:
            logger.error(f"Error adding file to watch: {filepath}, {e}")
    
    def periodic_scan(self):
        """Periodic scan for changes - backup mechanism"""
        if not os.path.exists(self.directory):
            return
            
        try:
            for filename in os.listdir(self.directory):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.directory, filename)
                    
                    # Check if file is being watched
                    if filepath not in self.watcher.files():
                        self._add_file_to_watch(filepath)
                    
                    # Check for modifications
                    try:
                        current_mtime = os.path.getmtime(filepath)
                        if filepath not in self.last_modification_times or \
                           current_mtime != self.last_modification_times[filepath]:
                            self._handle_file_change(filepath)
                    except FileNotFoundError:
                        # File was deleted
                        self._handle_file_deletion(filepath)
        except Exception as e:
            logger.error(f"Error in periodic scan: {e}")
    
    def on_directory_changed(self, path):
        """Handle directory change"""
        logger.debug(f"Directory changed: {path}")
        if os.path.exists(path):
            # Check for new files
            for filename in os.listdir(path):
                if filename.endswith('.json'):
                    filepath = os.path.join(path, filename)
                    if filepath not in self.watcher.files():
                        self._add_file_to_watch(filepath)
    
    def on_file_changed(self, filepath: str):
        """Handle file change from QFileSystemWatcher"""
        logger.debug(f"File changed signal: {filepath}")
        
        # Re-add the file to watcher as QFileSystemWatcher sometimes loses track
        if filepath not in self.watcher.files():
            self.watcher.addPath(filepath)
        
        self._handle_file_change(filepath)
    
    def _handle_file_change(self, filepath: str):
        """Handle file change with proper detection"""
        try:
            if not os.path.exists(filepath):
                return
                
            current_mtime = os.path.getmtime(filepath)
            content_changed = False
            
            # Check if content actually changed
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                    content_hash = hash(content)
                    
                    if filepath not in self.file_contents or \
                       content_hash != self.file_contents[filepath]:
                        content_changed = True
                        self.file_contents[filepath] = content_hash
            except Exception as e:
                logger.error(f"Error reading file: {filepath}, {e}")
                return
            
            if filepath not in self.last_modification_times or \
               current_mtime != self.last_modification_times[filepath] or \
               content_changed:
                
                self.last_modification_times[filepath] = current_mtime
                
                # Cancel any pending timer for this file
                if filepath in self.pending_changes:
                    self.pending_changes[filepath].stop()
                    self.pending_changes[filepath].deleteLater()
                
                # Create a new debounce timer
                timer = QTimer()
                timer.setSingleShot(True)
                timer.timeout.connect(lambda f=filepath: self._emit_file_changed(f))
                timer.start(200)  # 200ms debounce
                self.pending_changes[filepath] = timer
                
                logger.info(f"File change detected: {filepath}")
        except Exception as e:
            logger.error(f"Error handling file change: {filepath}, {e}")
    
    def _handle_file_deletion(self, filepath: str):
        """Handle file deletion"""
        # Remove from watcher
        if filepath in self.watcher.files():
            self.watcher.removePath(filepath)
        
        # Clean up tracking data
        if filepath in self.last_modification_times:
            del self.last_modification_times[filepath]
        if filepath in self.file_contents:
            del self.file_contents[filepath]
        if filepath in self.pending_changes:
            self.pending_changes[filepath].stop()
            self.pending_changes[filepath].deleteLater()
            del self.pending_changes[filepath]
        
        logger.info(f"File deleted: {filepath}")
    
    def _emit_file_changed(self, filepath: str):
        """Emit file changed signal after debounce"""
        logger.info(f"Emitting file changed signal: {filepath}")
        self.file_changed.emit(filepath)
        
        # Clean up timer
        if filepath in self.pending_changes:
            del self.pending_changes[filepath]
    
    def stop_watching(self):
        """Stop watching files and directory"""
        # Stop scan timer
        self.scan_timer.stop()
        
        # Stop all pending timers
        for timer in self.pending_changes.values():
            timer.stop()
            timer.deleteLater()
        self.pending_changes.clear()
        
        # Remove all paths from watcher
        if self.watcher:
            for path in self.watcher.files() + self.watcher.directories():
                self.watcher.removePath(path)
            logger.info(f"Stopped watching directory: {self.directory}")