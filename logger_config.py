import logging
import logging.handlers
import os
from datetime import datetime

class ScannerLogger:

    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.logger = None
        self.setup_logging()

    def setup_logging(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            print(f"[*] Created logs directory: {os.path.abspath(self.log_dir)}")

        self.logger = logging.getLogger('IoTScanner')
        self.logger.setLevel(logging.DEBUG)

        if self.logger.handlers:
            return

        log_file = os.path.join(self.log_dir, f"scanner_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=7
        )
        file_handler.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        self.logger.info("=" * 60)
        self.logger.info("IoT Scanner Logging System Initialized")
        self.logger.info(f"Log file: {os.path.abspath(log_file)}")
        self.logger.info("=" * 60)

    def get_logger(self):
        return self.logger