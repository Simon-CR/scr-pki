import time
import logging
import sys
import os
import asyncio
from datetime import datetime, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Certificate, CertificateStatus, MonitoringService, CheckResult, MonitoringStatus
from app.alerts import send_alert, get_config
from app.verifier import verify_remote_certificate

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

# Configuration
ALERT_CHECK_INTERVAL = int(os.getenv("ALERT_CHECK_INTERVAL", "3600")) # Default 1 hour
HEALTH_CHECK_INTERVAL = int(os.getenv("HEALTH_CHECK_INTERVAL", "300")) # Default 5 minutes

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
                if cert.status != CertificateStatus.EXPIRED:
                    logger.info(f"Marking certificate {cert.common_name} as EXPIRED")
                    cert.status = CertificateStatus.EXPIRED
                    db.commit()
            elif days_left <= 7:
                status = 'red'
            elif days_left <= alert_days_before_expiry:
                status = 'yellow'
            
            if status:
                logger.info(f"Certificate {cert.common_name} is {status} (Days left: {days_left})")
                await send_alert(cert.common_name, days_left, status)
                
    except Exception as e:
        logger.error(f"Error checking certificates: {e}")
    finally:
        db.close()
    logger.info("Certificate expiry check completed.")

async def check_uptime():
    logger.info("Starting uptime check...")
    db = next(get_db())
    try:
        # Get all certificates with monitoring enabled
        certs = db.query(Certificate).filter(
            Certificate.monitoring_enabled == True,
            Certificate.status == CertificateStatus.ACTIVE
        ).all()
        
        for cert in certs:
            try:
                # Find or create MonitoringService
                ms = db.query(MonitoringService).filter(MonitoringService.certificate_id == cert.id).first()
                if not ms:
                    # Create one
                    ms = MonitoringService(
                        name=f"Monitor for {cert.common_name}",
                        url=cert.monitoring_target_url or cert.common_name,
                        certificate_id=cert.id,
                        status=MonitoringStatus.ACTIVE
                    )
                    db.add(ms)
                    db.commit()
                    db.refresh(ms)
                
                # Perform check
                start_time = time.time()
                verification = verify_remote_certificate(cert)
                duration = time.time() - start_time
                
                # Update MonitoringService
                ms.last_check_at = datetime.now(timezone.utc)
                ms.last_check_duration = duration
                
                if verification["verification_error"]:
                    ms.last_check_result = CheckResult.FAILURE
                    ms.last_error_message = verification["verification_error"]
                elif verification["certificate_match"] is False:
                    ms.last_check_result = CheckResult.WARNING
                    ms.last_error_message = f"Serial mismatch: {verification['observed_serial_number']}"
                else:
                    ms.last_check_result = CheckResult.SUCCESS
                    ms.last_error_message = None
                    
                ms.update_statistics(ms.last_check_result, duration)
                db.commit()
            except Exception as e:
                logger.error(f"Error checking uptime for {cert.common_name}: {e}")
                db.rollback()
            
    except Exception as e:
        logger.error(f"Error checking uptime: {e}")
    finally:
        db.close()
    logger.info("Uptime check completed.")

def main():
    logger.info("Monitor service started")
    
    scheduler = AsyncIOScheduler()
    scheduler.add_job(check_certificates, 'interval', seconds=ALERT_CHECK_INTERVAL)
    scheduler.add_job(check_uptime, 'interval', seconds=HEALTH_CHECK_INTERVAL)
    scheduler.start()
    
    # Run the check immediately on startup
    loop = asyncio.get_event_loop()
    loop.run_until_complete(check_certificates())
    loop.run_until_complete(check_uptime())
    
    try:
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        pass

if __name__ == "__main__":
    main()
