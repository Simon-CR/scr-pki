import time
import logging
import sys
import os
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Certificate, CertificateStatus
from app.alerts import send_alert, get_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

# Configuration
ALERT_CHECK_INTERVAL = int(os.getenv("ALERT_CHECK_INTERVAL", "3600")) # Default 1 hour

async def check_certificates():
    logger.info("Starting certificate expiry check...")
    
    # Get configured days from DB, default to 30
    try:
        alert_days_config = get_config("alert_days_before_expiry", "30")
        alert_days_before_expiry = int(alert_days_config)
    except:
        alert_days_before_expiry = 30
        
    db = next(get_db())
    try:
        # Get all active certificates
        certs = db.query(Certificate).filter(
            Certificate.status.in_([CertificateStatus.ACTIVE, CertificateStatus.EXPIRED])
        ).all()
        
        for cert in certs:
            days_left = cert.days_until_expiry
            is_expired = cert.is_expired
            
            status = None
            if is_expired:
                status = 'expired'
            elif days_left <= 7:
                status = 'red'
            elif days_left <= alert_days_before_expiry:
                status = 'yellow'
            
            if status:
                logger.info(f"Certificate {cert.common_name} is {status} (Days left: {days_left})")
                # Only alert if monitoring is enabled for this cert? 
                # The user request implies a global system alert, but the model has `monitoring_enabled`.
                # Let's assume we alert for all active certs, or maybe check `monitoring_enabled`.
                # Given the user said "add a way to configure... alerts", and the model has `monitoring_enabled`,
                # maybe we should respect that flag.
                # However, expiration is critical regardless of "monitoring" (which usually implies uptime).
                # I'll alert for ALL certificates for now, as expiration is a core PKI function.
                # Or better, check if `monitoring_enabled` is true OR if it's a system cert?
                # Let's just alert for all.
                
                await send_alert(cert.common_name, days_left, status)
                
    except Exception as e:
        logger.error(f"Error checking certificates: {e}")
    finally:
        db.close()
    logger.info("Certificate expiry check completed.")

def main():
    logger.info("Monitor service started")
    
    scheduler = AsyncIOScheduler()
    scheduler.add_job(check_certificates, 'interval', seconds=ALERT_CHECK_INTERVAL)
    scheduler.start()
    
    # Run the check immediately on startup
    loop = asyncio.get_event_loop()
    loop.run_until_complete(check_certificates())
    
    try:
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        pass

if __name__ == "__main__":
    main()
