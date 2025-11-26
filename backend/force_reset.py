from app.core.database import SessionLocal
from app.api.v1.endpoints.system import reset_system
from app.models.user import User
import asyncio

# Mock dependencies
db = SessionLocal()
admin = db.query(User).filter(User.is_superuser == True).first()

if not admin:
    print("No admin user found!")
    exit(1)

async def run_reset():
    print("Forcing system reset with include_config=True...")
    try:
        await reset_system(include_config=True, db=db, current_user=admin)
        print("Reset completed successfully.")
    except Exception as e:
        print(f"Reset failed: {e}")

if __name__ == "__main__":
    asyncio.run(run_reset())
