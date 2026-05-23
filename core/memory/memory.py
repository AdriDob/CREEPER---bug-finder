from datetime import datetime
from typing import Any

from database.db import SessionLocal
from database.models import MemoryRecord


class MemoryEngine:
    def __init__(self):
        self.session = SessionLocal()

    def remember(self, category: str, key: str, details: dict[str, Any]) -> MemoryRecord:
        record = MemoryRecord(category=category, key=key, details=str(details))
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def recent(self, category: str, limit: int = 20) -> list[MemoryRecord]:
        return (
            self.session.query(MemoryRecord)
            .filter(MemoryRecord.category == category)
            .order_by(MemoryRecord.created_at.desc())
            .limit(limit)
            .all()
        )

    def close(self):
        self.session.close()
