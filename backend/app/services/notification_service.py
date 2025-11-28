"""
Notification service for sending alerts via Email, etc.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, List
import structlog

from sqlalchemy.orm import Session
from app.models.system import SystemConfig
from app.models.certificate import Certificate

logger = structlog.get_logger(__name__)

class NotificationService:
    
    def get_smtp_settings(self, db: Session):
        """Retrieve SMTP settings from the database."""
        settings = {}
        configs = db.query(SystemConfig).all()
        for config in configs:
            settings[config.key] = config.value
            
        return settings

    def send_email(self, db: Session, to_email: str, subject: str, body: str) -> bool:
        """Send an email using stored SMTP settings."""
        settings = self.get_smtp_settings(db)
        
        # Check if SMTP is enabled
        if settings.get("smtp_enabled", "false").lower() != "true":
            logger.warning("SMTP is disabled, skipping email", to=to_email, subject=subject)
            return False

        smtp_host = settings.get("smtp_host")
        smtp_port = int(settings.get("smtp_port", 587))
        smtp_username = settings.get("smtp_username")
        smtp_password = settings.get("smtp_password")
        smtp_use_tls = settings.get("smtp_use_tls", "true").lower() == "true"
        email_from = settings.get("alert_email_from")

        if not smtp_host or not email_from:
            logger.error("SMTP host or From address not configured")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = email_from
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_host, smtp_port)
            if smtp_use_tls:
                server.starttls()
            
            if smtp_username and smtp_password:
                server.login(smtp_username, smtp_password)
                
            server.send_message(msg)
            server.quit()
            
            logger.info("Email sent successfully", to=to_email, subject=subject)
            return True
            
        except Exception as e:
            logger.error("Failed to send email", error=str(e))
            return False

    def send_expiration_alert(self, db: Session, cert: Certificate, days_remaining: int):
        """Send an expiration alert for a certificate."""
        settings = self.get_smtp_settings(db)
        to_email = settings.get("alert_email_to")
        
        if not to_email:
            logger.warning("No alert recipient configured (alert_email_to)")
            return

        subject = f"Certificate Expiration Warning: {cert.common_name}"
        body = f"""
        Certificate Expiration Warning
        
        The following certificate is expiring soon:
        
        Common Name: {cert.common_name}
        Serial Number: {cert.serial_number}
        Expires On: {cert.not_valid_after}
        Days Remaining: {days_remaining}
        
        Please renew this certificate before it expires.
        
        --
        SCR-PKI System
        """
        
        self.send_email(db, to_email, subject, body)

notification_service = NotificationService()
