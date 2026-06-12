import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add backend app to python path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.database import Base, SessionLocal, engine
from app import models
from app.main import run_background_scan

def run_reproduction():
    print("Initializing reproduction script...")
    
    # 1. Simulate the test database setup (in-memory SQLite)
    test_engine = create_engine("sqlite:///:memory:")
    TestingSessionLocal = sessionmaker(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    
    # Create the test db session
    test_db = TestingSessionLocal()
    
    # 2. Add a scan to the test database (mimicking client.post in tests)
    print("Creating scan record in in-memory test database...")
    test_scan = models.Scan(
        target="127.0.0.1",
        profile="quick",
        status="running"
    )
    test_db.add(test_scan)
    test_db.commit()
    test_db.refresh(test_scan)
    scan_id = test_scan.id
    print(f"Created scan ID: {scan_id} in test database. Status: {test_scan.status}")
    
    # 3. Call the background scan function (which is under test)
    # Under the hood, this function queries the real database (SessionLocal)
    print("Running background scan (run_background_scan)...")
    try:
        run_background_scan(scan_id, "127.0.0.1", "quick")
    except Exception as e:
        print(f"Got exception during background scan: {e}")
        
    # 4. Check the status in the test database
    test_db.refresh(test_scan)
    print(f"Scan status in test database after background task: {test_scan.status}")
    
    if test_scan.status == "completed":
        print("SUCCESS: Scan status is completed. (Unexpected if database mismatch occurred)")
    else:
        print("FAILURE/CONFIRMED BUG: Scan status remains 'running'.")
        print("This is because the background task searched for the scan in the real database file, not the test database!")

if __name__ == "__main__":
    run_reproduction()
