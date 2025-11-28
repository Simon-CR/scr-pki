# QA Gaps and TODO List

This document tracks identified gaps in the SCR-PKI project and the plan to address them.

## 🔍 QA Findings

1.  **Monitoring & Alerting (Critical Gap)**
    *   **Observation:** While the code has the logic to verify a certificate (`monitoring_verifier.py`) and send a test email (`system.py`), there is **no background scheduler** (like `APScheduler` or a `cron` job) to run these checks automatically.
    *   **Impact:** "Automated health checks" and "Expiration alerts" features listed in the README are currently non-functional. Alerts are only generated when the `/alerts` endpoint is manually queried.
    *   **Missing:** A background task runner to periodically:
        *   Check monitored services.
        *   Scan for expiring certificates.
        *   Send email notifications.

2.  **Alert Management**
    *   **Observation:** The `POST /alerts/{id}/acknowledge` endpoint raises a `501 Not Implemented` error.
    *   **Impact:** Users cannot acknowledge or dismiss alerts in the UI.

3.  **Audit Logging**
    *   **Observation:** "Audit logging" is listed as a completed feature. While the system logs requests to `stdout` (via `structlog`), there is no dedicated database table or API endpoint to query these logs.
    *   **Impact:** The "Audit Logging" feature is limited to server logs and is not accessible via the UI.

4.  **Documentation Discrepancies**
    *   **Observation:** `ROADMAP.md` marks "Email notifications" as completed `[x]`, but without the background scheduler, no actual notifications are sent (only manual test emails).
    *   **Observation:** `ROADMAP.md` lists "Intermediate CA Support" for v1.3.0, but the backend code (`ca_service.py`) already supports creating intermediate CAs.

## 📝 TODO List

### 1. Implement Background Scheduler (High Priority)
- [x] **Add Scheduler Library:** Install `apscheduler` in `backend/requirements.txt`. (Already present)
- [x] **Create Scheduler Service:** Create `backend/app/services/scheduler.py` to manage background jobs.
- [x] **Implement Monitoring Job:** Create a job that runs every `HEALTH_CHECK_INTERVAL` to:
    - Query all monitored certificates.
    - Run `verify_remote_certificate` for each.
    - Update the database with results.
- [x] **Implement Expiration Job:** Create a daily job to:
    - Query certificates expiring within `ALERT_DAYS_BEFORE_EXPIRY`.
    - Send email notifications using the logic from `system.py`.
- [x] **Initialize Scheduler:** Start the scheduler in `backend/app/main.py`'s `lifespan` event.

### 2. Fix Alert Management
- [x] **Implement Acknowledgment:** Update `backend/app/api/v1/endpoints/alerts.py` to handle alert acknowledgment (requires adding an `acknowledged` field or table to track state).

### 3. Documentation Updates
- [x] **Update Roadmap:** Uncheck "Email notifications" until the scheduler is implemented. (Scheduler implemented, feature is now active)
- [x] **Update Roadmap:** Mark "Intermediate CA Support" as completed (or partially completed) if the backend supports it.
- [x] **Clarify Audit Logging:** Update documentation to clarify that audit logs are currently server-side only.

### 4. Cleanup (Low Priority)
- [x] **CSR Support:** Confirm if CSR support is intended for a later release (as per roadmap) or if `pki_service.py` should be extended now. (Confirmed: Scheduled for v1.3.0).
