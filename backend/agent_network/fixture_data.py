"""Fixture data generator and loader: 50 realistic student records with canary markers and honeypots."""
from __future__ import annotations
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from agent_network.models import StudentRecord

CANARY_STUDENT_IDS = ["STU-2026-007", "STU-2026-023", "STU-2026-042"]
DECOY_STUDENT_ID = "STU-DECOY-9999"

FIRST_NAMES = [
    "Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Reyansh", "Muhammad", "Sai",
    "Aanya", "Diya", "Saanvi", "Ananya", "Ishita", "Pari", "Myra", "Neha",
    "Rohan", "Vikram", "Kavya", "Rahul", "Pooja", "Siddharth", "Tanvi", "Amit",
    "Sneha", "Kunal", "Meera", "Deepak", "Riya", "Karan", "Shreya", "Nikhil",
    "Divya", "Gaurav", "Anjali", "Harsh", "Priyanka", "Varun", "Swati", "Manish",
    "Komal", "Rajesh", "Simran", "Alok", "Preeti", "Suresh", "Bhavna", "Abhishek",
    "Sunita", "Tarun"
]

LAST_NAMES = [
    "Sharma", "Verma", "Patel", "Gupta", "Iyer", "Singh", "Reddy", "Mehta",
    "Kumar", "Nair", "Choudhary", "Joshi", "Bose", "Das", "Rao", "Mishra",
    "Chatterjee", "Kulkarni", "Deshmukh", "Chawla"
]

DEPARTMENTS = ["Computer Science", "Electronics & Comm", "Mechanical Eng", "Civil Eng", "Data Science & AI"]


def generate_student_records(count: int = 50) -> List[StudentRecord]:
    records: List[StudentRecord] = []
    
    for i in range(1, count + 1):
        stu_id = f"STU-2026-{i:03d}"
        first = FIRST_NAMES[(i - 1) % len(FIRST_NAMES)]
        last = LAST_NAMES[(i - 1) % len(LAST_NAMES)]
        dept = DEPARTMENTS[(i - 1) % len(DEPARTMENTS)]
        semester = ((i - 1) % 8) + 1
        
        # Determine fees and standing
        fee_total = 120000.0
        if i % 3 == 0:
            fee_status = "overdue"
            fee_balance = 65000.0
        elif i % 2 == 0:
            fee_status = "pending"
            fee_balance = 30000.0
        else:
            fee_status = "paid"
            fee_balance = 0.0

        gpa = round(6.5 + (i * 0.065) % 3.4, 2)
        academic_standing = "honors" if gpa >= 9.0 else ("probation" if gpa < 7.0 else "good")

        is_canary = stu_id in CANARY_STUDENT_IDS
        canary_marker = f"CANARY-TOKEN-{uuid.uuid5(uuid.NAMESPACE_DNS, stu_id).hex[:12].upper()}" if is_canary else None

        records.append(StudentRecord(
            student_id=stu_id,
            name=f"{first} {last}",
            email=f"{first.lower()}.{last.lower()}@campus.edu",
            department=dept,
            semester=semester,
            fee_total=fee_total,
            fee_balance=fee_balance,
            fee_status=fee_status,
            gpa=gpa,
            academic_standing=academic_standing,
            is_canary=is_canary,
            canary_marker=canary_marker,
            is_decoy=False
        ))

    # Add the Honeypot Decoy Record (Section 7 & Phase 2)
    records.append(StudentRecord(
        student_id=DECOY_STUDENT_ID,
        name="Administrator HoneyAccount",
        email="root.honeypot@campus.edu",
        department="Administrative Secret Service",
        semester=99,
        fee_total=999999.0,
        fee_balance=999999.0,
        fee_status="overdue",
        gpa=10.0,
        academic_standing="honors",
        is_canary=False,
        canary_marker=None,
        is_decoy=True
    ))

    return records


class StudentDatabase:
    """In-memory and file-backed database of student records."""

    def __init__(self, data_file: Path | str | None = None):
        self._records: Dict[str, StudentRecord] = {}
        self.data_file = Path(data_file) if data_file else Path(__file__).resolve().parents[1] / "data" / "student_records.json"
        self._load_or_generate()

    def _load_or_generate(self):
        if self.data_file.exists():
            try:
                data = json.loads(self.data_file.read_text(encoding="utf-8"))
                for item in data:
                    rec = StudentRecord.model_validate(item)
                    self._records[rec.student_id] = rec
                return
            except Exception:
                pass

        # Generate fresh records
        records = generate_student_records(50)
        for r in records:
            self._records[r.student_id] = r
        self.save()

    def save(self):
        try:
            self.data_file.parent.mkdir(parents=True, exist_ok=True)
            raw = [r.model_dump() for r in self._records.values()]
            self.data_file.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        except Exception:
            pass

    def get(self, student_id: str) -> Optional[StudentRecord]:
        return self._records.get(student_id)

    def list_all(self) -> List[StudentRecord]:
        return list(self._records.values())

    def get_canary_records(self) -> List[StudentRecord]:
        return [r for r in self._records.values() if r.is_canary]

    def get_decoy_record(self) -> Optional[StudentRecord]:
        return self._records.get(DECOY_STUDENT_ID)


STUDENT_DB = StudentDatabase()
