import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiohttp
import json
from app.database import SessionLocal
from app.models import SystemConfig

logger = logging.getLogger(__name__)

def get_config(key: str, default: str = None) -> str:
    db = SessionLocal()
    try:
        config = db.query(SystemConfig).filter(SystemConfig.key == key).first()
        if config:
            # logger.info(f"Loaded config {key}: {config.value}") # Debug
            return config.value
        logger.debug(f"Config key not found: {key}")
        return default
    except Exception as e:
        logger.error(f"Error fetching config for {key}: {e}")
        return default
    finally:
        db.close()

def get_bool_config(key: str, default: str = "false") -> bool:
    val = get_config(key, default)
    if val is None:
        return default.lower() == "true"
    return val.lower() == "true"

async def send_email_alert(subject: str, body: str):
    if not get_bool_config("smtp_enabled"):
        logger.info("SMTP is disabled in configuration. Skipping email alert.")
        return
    
    smtp_host = get_config("smtp_host")
    smtp_port = int(get_config("smtp_port", "587"))
    smtp_username = get_config("smtp_username")
    smtp_password = get_config("smtp_password")
    smtp_use_tls = get_bool_config("smtp_use_tls", "true")
    email_from = get_config("alert_email_from")
    email_to = get_config("alert_email_to")

    if not smtp_host or not email_from or not email_to:
        logger.warning(f"SMTP enabled but missing configuration. Host: {smtp_host}, From: {email_from}, To: {email_to}")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = email_from
        msg['To'] = email_to
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        logger.info(f"Connecting to SMTP server {smtp_host}:{smtp_port}...")
        server = smtplib.SMTP(smtp_host, smtp_port)
        if smtp_use_tls:
            server.starttls()
        
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
            
        server.send_message(msg)
        server.quit()
        logger.info(f"Email alert sent: {subject}")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")

async def send_slack_alert(message: str, color: str = "#danger"):
    if not get_bool_config("webhook_slack_enabled"):
        return

    webhook_url = get_config("webhook_slack_url")
    if not webhook_url:
        return

    payload = {
        "attachments": [
            {
                "color": color,
                "text": message,
                "mrkdwn_in": ["text"]
            }
        ]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as response:
                if response.status != 200:
                    logger.error(f"Failed to send Slack alert: {response.status}")
                else:
                    logger.info("Slack alert sent")
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")

async def send_discord_alert(message: str, color: int = 15158332): # Red default
    if not get_bool_config("webhook_discord_enabled"):
        return

    webhook_url = get_config("webhook_discord_url")
    if not webhook_url:
        return

    payload = {
        "embeds": [
            {
                "description": message,
                "color": color
            }
        ]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as response:
                if response.status not in [200, 204]:
                    logger.error(f"Failed to send Discord alert: {response.status}")
                else:
                    logger.info("Discord alert sent")
    except Exception as e:
        logger.error(f"Failed to send Discord alert: {e}")

async def send_alert(cert_cn: str, days_left: int, status: str):
    """
    Send alert via configured channels.
    status: 'yellow', 'red', 'expired'
    """
    subject = f"Certificate Alert: {cert_cn}"
    
    if status == 'expired':
        message = f"🚨 **CRITICAL**: Certificate for **{cert_cn}** has EXPIRED! (Expired {abs(days_left)} days ago)"
        color_slack = "#ff0000"
        color_discord = 15548997 # Red
    elif status == 'red':
        message = f"⚠️ **URGENT**: Certificate for **{cert_cn}** expires in {days_left} days!"
        color_slack = "#ff4500"
        color_discord = 15105570 # Orange
    else: # yellow
        message = f"⚠️ **WARNING**: Certificate for **{cert_cn}** expires in {days_left} days."
        color_slack = "#ffd700"
        color_discord = 16776960 # Yellow

    # Send to all enabled channels
    await send_email_alert(subject, message.replace("**", ""))
    await send_slack_alert(message, color_slack)
    await send_discord_alert(message, color_discord)
