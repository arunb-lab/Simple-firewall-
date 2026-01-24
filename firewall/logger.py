import json
from datetime import datetime
from pathlib import Path

class FirewallLogger:
    def __init__(self, logfile: str = "firewall.log"):
        self.logfile = Path(logfile)

    def log(self, record: dict):
        record = dict(record)
        record["timestamp"] = datetime.utcnow().isoformat() + "Z"
        with self.logfile.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
