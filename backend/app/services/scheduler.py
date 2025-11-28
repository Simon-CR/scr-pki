"""
Scheduler service for running background tasks.
"""
import structlog
from datetime import datetime, timedelta, timezone
from typing import List

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.certificate import Certificate, CertificateStatus
from app.models.monitoring import MonitoringService, CheckResult, MonitoringStatus
from app.models.system import SystemConfig
from app.services.monitoring_verifier import verify_remote_certificate
from app.services.notification_service import notification_service

logger = structlog.get_logger(__name__)

class SchedulerService:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self._is_running = False

    def start(self):
        """Start the scheduler."""
        if self._is_running:
            return

        logger.info("Starting background scheduler")
        
        # Add jobs
        self.scheduler.add_job(
            self.check_monitored_services,
            trigger=IntervalTrigger(minutes=5),
            id='check_monitored_services',
            name='Check monitored services',
            replace_existing=True
        )
        
        self.scheduler.add_job(
            self.check_expiring_certificates,
            trigger=IntervalTrigger(hours=24),
            id='check_expiring_certificates',
            name='Check expiring certificates',
            replace_existing=True
        )

        self.scheduler.start()
        self._is_running = True

    def stop(self):
        """Stop the scheduler."""
        if self._is_running:
            logger.info("Stopping background scheduler")
            self.scheduler.shutdown()
            self._is_running = False

    def check_monitored_services(self):
        """Check status of all monitored services."""
        logger.info("Running scheduled job: check_monitored_services")
        db = SessionLocal()
        try:
            # Find certificates with monitoring enabled
            certs = db.query(Certificate).filter(
                Certificate.monitoring_enabled == True,
                Certificate.status == CertificateStatus.VALID
            ).all()
            
            logger.info(f"Found {len(certs)} services to monitor")
            
            for cert in certs:
                try:
                    # Get or create MonitoringService record
                    monitor = db.query(MonitoringService).filter(
                        MonitoringService.certificate_id == cert.id
                    ).first()
                    
                    if not monitor:
                        monitor = MonitoringService(
                            name=f"Monitor for {cert.common_name}",
                            url=cert.monitoring_target_url or f"https://{cert.common_name}",
                            certificate_id=cert.id,
                            status=MonitoringStatus.ACTIVE
                        )
                        db.add(monitor)
                        db.commit()
                        db.refresh(monitor)

                    result = verify_remote_certificate(cert)
                    
                    # Update monitoring record
                    monitor.last_check_at = datetime.now(timezone.utc)
                    monitor.total_checks += 1
                    
                    error = result.get("verification_error")
                    match = result.get("certificate_match")
                    
                    if error:
                        monitor.last_check_result = CheckResult.FAILURE
                        monitor.last_error_message = str(error)
                        monitor.consecutive_failures += 1
                        monitor.failed_checks += 1
                        
                        logger.warning("Monitoring check failed", 
                                     cert_id=cert.id, 
                                     common_name=cert.common_name,
                                     error=error)
                    elif match is False:
                        monitor.last_check_result = CheckResult.WARNING
                        monitor.last_error_message = f"Certificate mismatch. Observed: {result.get('observed_serial_number')}"
                        monitor.consecutive_failures += 1 # Treat mismatch as a failure type for alerting
                        monitor.failed_checks += 1
                        
                        logger.warning("Monitoring certificate mismatch", 
                                     cert_id=cert.id, 
                                     common_name=cert.common_name,
                                     observed_serial=result.get("observed_serial_number"))
                    else:
                        monitor.last_check_result = CheckResult.SUCCESS
                        monitor.last_error_message = None
                        monitor.consecutive_failures = 0
                        monitor.successful_checks += 1
                        
                        logger.info("Monitoring check passed", 
                                  cert_id=cert.id, 
                                  common_name=cert.common_name)
                    
                    db.commit()
                                  
                except Exception as e:
                    logger.error("Error monitoring certificate", 
                               cert_id=cert.id, 
                               error=str(e))
                               
        except Exception as e:
            logger.error("Error in check_monitored_services job", error=str(e))
        finally:
            db.close()

    def check_expiring_certificates(self):
        """Check for expiring certificates and send alerts."""
        logger.info("Running scheduled job: check_expiring_certificates")
        db = SessionLocal()
        try:
            # Get alert threshold from config
            threshold_config = db.query(SystemConfig).filter(
                SystemConfig.key == "alert_days_before_expiration"
            ).first()
            
            days_threshold = int(threshold_config.value) if threshold_config else 30
            
            warning_date = datetime.now(timezone.utc) + timedelta(days=days_threshold)
            
            # Find valid certificates expiring soon
            expiring_certs = db.query(Certificate).filter(
                Certificate.status == CertificateStatus.VALID,
                Certificate.not_valid_after <= warning_date,
                Certificate.not_valid_after > datetime.now(timezone.utc) # Not already expired
            ).all()
            
            logger.info(f"Found {len(expiring_certs)} expiring certificates")
            
            for cert in expiring_certs:
                days_remaining = (cert.not_valid_after - datetime.now(timezone.utc)).days
                logger.info("Sending expiration alert", 
                          cert_id=cert.id, 
                          days_remaining=days_remaining)
                
                notification_service.send_expiration_alert(db, cert, days_remaining)
                
        except Exception as e:
            logger.error("Error in check_expiring_certificates job", error=str(e))
        finally:
            db.close()

scheduler_service = SchedulerService()
