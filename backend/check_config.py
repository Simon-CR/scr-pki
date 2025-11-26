from app.core.database import SessionLocal
from app.models.system import SystemConfig

db = SessionLocal()
configs = db.query(SystemConfig).all()
print(f"Found {len(configs)} config entries:")
for c in configs:
    print(f"  {c.key}: {c.value}")
db.close()
