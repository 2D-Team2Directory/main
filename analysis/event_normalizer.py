from datetime import datetime, timezone
from typing import Optional, Any


def _to_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def get_event_type(event_id: Optional[str]) -> str:
    eid = _to_str(event_id)

    mapping = {
        "4624": "login_success",
        "4625": "login_failure",
        "4720": "account_created",
        "4722": "account_enabled",
        "4725": "account_disabled",
        "4726": "account_deleted",
        "4728": "group_change",
        "4732": "group_change",
        "4756": "group_change",
        "4768": "kerberos_request",
        "4769": "kerberos_request",
        "4771": "kerberos_failure",
        "4648": "explicit_credentials_logon",
        "4688": "process_create",
    }

    return mapping.get(eid, "unknown")


def get_host_role(computer_name: Optional[str]) -> str:
    if not computer_name:
        return "unknown"

    name = computer_name.lower()

    if "dc" in name or "domaincontroller" in name:
        return "dc"
    if "server" in name or "srv" in name:
        return "server"
    return "client"


def is_admin_name(name: Optional[str]) -> bool:
    if not name:
        return False

    lowered = name.lower()
    admin_keywords = [
        "administrator",
        "admin",
        "domain admin",
        "enterprise admin",
        "krbtgt",
    ]
    return any(keyword in lowered for keyword in admin_keywords)


def get_account_type(username: Optional[str], target_user: Optional[str]) -> str:
    name = target_user or username
    if not name:
        return "unknown"

    lowered = name.lower()

    if name.endswith("$"):
        return "machine"

    service_keywords = ["svc", "service", "sql", "iis", "apache", "backup"]
    if any(keyword in lowered for keyword in service_keywords):
        return "service"

    if is_admin_name(name):
        return "admin"

    return "user"


def is_privileged_account(username: Optional[str], target_user: Optional[str]) -> bool:
    return get_account_type(username, target_user) in ["admin", "service"]


def is_off_hours_time(event_time: Optional[str]) -> bool:
    if not event_time:
        return False

    try:
        dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.hour < 8 or dt.hour >= 20
    except Exception:
        return False


def get_logon_type_name(logon_type: Optional[str]) -> Optional[str]:
    value = _to_str(logon_type)
    if value is None:
        return None

    mapping = {
        "2": "interactive",
        "3": "network",
        "4": "batch",
        "5": "service",
        "7": "unlock",
        "8": "network_cleartext",
        "9": "new_credentials",
        "10": "remote_interactive",
        "11": "cached_interactive",
    }

    return mapping.get(value, "unknown")


def normalize_event(event) -> dict:
    username = getattr(event, "username", None)
    target_user = getattr(event, "target_user", None)
    computer_name = getattr(event, "computer_name", None)
    group_name = getattr(event, "group_name", None)
    source_ip = getattr(event, "source_ip", None)
    target_host = getattr(event, "target_host", None)
    service_name = getattr(event, "service_name", None)
    logon_type = getattr(event, "logon_type", None)
    event_time = getattr(event, "event_time", None)
    event_id = getattr(event, "event_id", None)

    return {
        "event_type": get_event_type(event_id),
        "event_id": _to_str(event_id),
        "host_role": get_host_role(computer_name),
        "account_type": get_account_type(username, target_user),
        "is_admin_account": is_admin_name(target_user or username),
        "is_privileged": is_privileged_account(username, target_user),
        "is_off_hours": is_off_hours_time(event_time),
        "username": username,
        "target_user": target_user,
        "group_name": group_name,
        "source_ip": source_ip,
        "computer_name": computer_name,
        "target_host": target_host,
        "service_name": service_name,
        "logon_type_name": get_logon_type_name(logon_type),
    }