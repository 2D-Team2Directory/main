from analysis.detection_engine import evaluate_event


def make_event(username: str, event_time: str):
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
        make_event("administrator", "2026-04-17T10:00:00Z"),
        make_event("administrator", "2026-04-17T10:00:20Z"),
        make_event("administrator", "2026-04-17T10:00:40Z"),
        make_event("administrator", "2026-04-17T10:01:00Z"),
        make_event("administrator", "2026-04-17T10:01:20Z"),
        make_event("administrator", "2026-04-17T10:01:40Z"),
        make_event("administrator", "2026-04-17T10:02:00Z"),
        make_event("administrator", "2026-04-17T10:02:20Z"),
        make_event("administrator", "2026-04-17T10:02:40Z"),
    ]

    current_event = make_event("administrator", "2026-04-17T10:03:00Z")

    result = evaluate_event(
        event_dict=current_event["event"],
        normalized=current_event["normalized"],
        recent_events=recent_events
    )

    print("result =", result)