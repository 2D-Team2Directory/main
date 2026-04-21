from analysis.bundle_builder import build_event_bundle


class DummyEvent:
    def __init__(
        self,
        event_time,
        event_id,
        provider,
        channel,
        level,
        computer_name,
        username,
        source_ip,
        target_user,
        target_host,
        group_name,
        logon_type,
        service_name,
        message,
        raw_json,
    ):
        self.event_time = event_time
        self.event_id = event_id
        self.provider = provider
        self.channel = channel
        self.level = level
        self.computer_name = computer_name
        self.username = username
        self.source_ip = source_ip
        self.target_user = target_user
        self.target_host = target_host
        self.group_name = group_name
        self.logon_type = logon_type
        self.service_name = service_name
        self.message = message
        self.raw_json = raw_json


def make_recent_event(username: str, event_time: str):
    return {
        "event": {
            "event_time": event_time,
            "event_id": "4625",
            "username": username,
            "target_user": username,
            "computer_name": "CLIENT-01",
            "message": "An account failed to log on."
        },
        "normalized": {
            "event_type": "login_failure",
            "host_role": "client",
            "account_type": "admin" if username == "administrator" else "user",
            "is_admin_account": username == "administrator",
            "is_privileged": username == "administrator",
            "is_off_hours": True
        }
    }


if __name__ == "__main__":
    recent_events = [
        make_recent_event("administrator", "2026-04-17T10:00:00Z"),
        make_recent_event("administrator", "2026-04-17T10:00:20Z"),
        make_recent_event("administrator", "2026-04-17T10:00:40Z"),
        make_recent_event("administrator", "2026-04-17T10:01:00Z"),
        make_recent_event("administrator", "2026-04-17T10:01:20Z"),
        make_recent_event("administrator", "2026-04-17T10:01:40Z"),
        make_recent_event("administrator", "2026-04-17T10:02:00Z"),
        make_recent_event("administrator", "2026-04-17T10:02:20Z"),
        make_recent_event("administrator", "2026-04-17T10:02:40Z"),
    ]

    current_event = DummyEvent(
        event_time="2026-04-17T10:03:00Z",
        event_id="4625",
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        level="warning",
        computer_name="CLIENT-01",
        username="administrator",
        source_ip="192.168.56.10",
        target_user="administrator",
        target_host="DC-01",
        group_name=None,
        logon_type="3",
        service_name=None,
        message="An account failed to log on.",
        raw_json="{}",
    )

    result = build_event_bundle(current_event, recent_events=recent_events)
    print(result)