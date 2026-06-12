import datetime
import sys
import os

# Add backend app to python path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.database import Base, engine, SessionLocal
from app import models

def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Clear existing to ensure clean seed IDs
        db.query(models.ScanResult).delete()
        db.query(models.Scan).delete()
        db.query(models.Alert).delete()
        db.commit()

        # Seed Scan 1 (Quick Scan, no vulnerabilities)
        scan1 = models.Scan(
            id=1,
            target="192.168.1.1",
            profile="quick",
            status="completed",
            created_at=datetime.datetime.utcnow()
        )
        db.add(scan1)
        db.commit()

        res1 = models.ScanResult(
            scan_id=1,
            port=80,
            protocol="TCP",
            state="open",
            status="open",
            service="http",
            vulnerabilities=""
        )
        res2 = models.ScanResult(
            scan_id=1,
            port=443,
            protocol="TCP",
            state="open",
            status="open",
            service="https",
            vulnerabilities=""
        )
        db.add_all([res1, res2])

        # Seed Scan 2 (Full Scan, with vulnerabilities)
        scan2 = models.Scan(
            id=2,
            target="10.0.0.1",
            profile="full",
            status="completed",
            created_at=datetime.datetime.utcnow()
        )
        db.add(scan2)
        db.commit()

        res3 = models.ScanResult(
            scan_id=2,
            port=22,
            protocol="TCP",
            state="open",
            status="open",
            service="ssh",
            vulnerabilities=""
        )
        res4 = models.ScanResult(
            scan_id=2,
            port=80,
            protocol="TCP",
            state="open",
            status="open",
            service="http",
            vulnerabilities="CVE-2021-41773"
        )
        res5 = models.ScanResult(
            scan_id=2,
            port=8080,
            protocol="TCP",
            state="open",
            status="open",
            service="http-alt",
            vulnerabilities="CVE-2024-XXXX"
        )
        db.add_all([res3, res4, res5])

        # Seed Alert 1
        alert1 = models.Alert(
            id=1,
            timestamp=datetime.datetime.utcnow(),
            source_ip="10.0.0.50",
            destination_ip="10.0.0.1",
            protocol="TCP",
            alert_type="Port Scan",
            description="Suspicious scan activity on ports 22, 80, 8080",
            severity="medium"
        )
        db.add(alert1)
        db.commit()

        print("Database seeded successfully for E2E tests!")
    finally:
        db.close()

if __name__ == "__main__":
    seed()
