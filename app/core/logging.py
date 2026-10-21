import logging
import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def setup_logging(debug: bool = True) -> logging.Logger:
    """
    Configures application-wide structured logging.
    """
    log_level = logging.DEBUG if debug else logging.INFO
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger("grc_platform")
    root_logger.setLevel(log_level)
    
    # Avoid duplicate handlers if reloaded
    if not root_logger.handlers:
        root_logger.addHandler(handler)

    # Prevent propagation to avoid double logging with uvicorn root
    root_logger.propagate = False
    return root_logger


logger = setup_logging()
security_logger = logging.getLogger("grc_platform.security")


def log_security_event(
    event_type: str,
    status: str,
    user_email: Optional[str] = None,
    org_id: Optional[int] = None,
    client_ip: Optional[str] = None,
    resource: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    severity: str = "INFO"
) -> None:
    """
    Structured security event audit logger.
    Used for monitoring authentication attempts, privilege escalation,
    cross-tenant boundaries, and compliance state mutations.
    """
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "status": status,
        "severity": severity.upper(),
        "user_email": user_email or "anonymous",
        "org_id": org_id,
        "client_ip": client_ip or "unknown",
        "resource": resource or "general",
        "details": details or {}
    }

    message = f"SECURITY_AUDIT | {event_type} | {status} | User={payload['user_email']} | Org={org_id} | IP={payload['client_ip']} | Resource={payload['resource']} | Details={json.dumps(payload['details'])}"

    sev = severity.upper()
    if sev == "CRITICAL":
        security_logger.critical(message, extra={"security_event": payload})
    elif sev in ("ERROR", "HIGH"):
        security_logger.error(message, extra={"security_event": payload})
    elif sev in ("WARNING", "MEDIUM"):
        security_logger.warning(message, extra={"security_event": payload})
    else:
        security_logger.info(message, extra={"security_event": payload})
