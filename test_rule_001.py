import yaml
from analysis.evaluators.aggregation import evaluate_aggregation_rule


def load_rule_001():
    with open("analysis/rules/detection_rules.yaml", "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    for rule in data["rules"]:
        if rule["rule_id"] == "RULE-001":
            return rule

    raise ValueError("RULE-001 not found")


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


def run_test_case(case_name, current_event, recent_events):
    rule = load_rule_001()

    result = evaluate_aggregation_rule(
        rule=rule,
        event_dict=current_event["event"],
        normalized=current_event["normalized"],
        recent_events=recent_events
    )

    print(f"\n===== {case_name} =====")
    print("result =", result)


if __name__ == "__main__":
    # 테스트 1: 같은 계정 9회 -> 탐지 안 돼야 함
    recent_events_9 = [
        make_event("user1", "2026-04-17T10:00:00Z"),
        make_event("user1", "2026-04-17T10:00:20Z"),
        make_event("user1", "2026-04-17T10:00:40Z"),
        make_event("user1", "2026-04-17T10:01:00Z"),
        make_event("user1", "2026-04-17T10:01:20Z"),
        make_event("user1", "2026-04-17T10:01:40Z"),
        make_event("user1", "2026-04-17T10:02:00Z"),
        make_event("user1", "2026-04-17T10:02:20Z"),
        make_event("user1", "2026-04-17T10:02:40Z"),
    ]

    # 8개만 recent로 주고 현재 이벤트 1개 -> 총 9회
    current_event_9 = make_event("user1", "2026-04-17T10:03:00Z")
    run_test_case("테스트1 - 총 9회", current_event_9, recent_events_9[:8])

    # 9개 recent + 현재 이벤트 1개 -> 총 10회
    current_event_10 = make_event("user1", "2026-04-17T10:03:00Z")
    run_test_case("테스트2 - 총 10회", current_event_10, recent_events_9)

    # 관리자 계정 9개 recent + 현재 이벤트 1개 -> 총 10회, +20 가중치
    admin_recent_events = [
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
    current_admin_event = make_event("administrator", "2026-04-17T10:03:00Z")
    run_test_case("테스트3 - 관리자 총 10회", current_admin_event, admin_recent_events)