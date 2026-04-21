from analysis.detection_engine import evaluate_event
from analysis.event_normalizer import normalize_event


class DummyEvent:
    def __init__(self, event_time, event_id, computer_name, username, target_user, group_name=None):
        self.event_time = event_time
        self.event_id = event_id
        self.provider = "Microsoft-Windows-Security-Auditing"
        self.channel = "Security"
        self.level = "information"
        self.computer_name = computer_name
        self.username = username
        self.source_ip = "192.168.56.10"
        self.target_user = target_user
        self.target_host = None
        self.group_name = group_name
        self.logon_type = "3"
        self.service_name = None
        self.message = "test event"
        self.raw_json = "{}"


def run_case(name, event_id, username, target_user, group_name=None):
    event = DummyEvent(
        event_time="2026-04-20T10:00:00Z",
        event_id=event_id,
        computer_name="CLIENT-01",
        username=username,
        target_user=target_user,
        group_name=group_name
    )

    event_dict = {
        "event_time": event.event_time,
        "event_id": str(event.event_id),
        "provider": event.provider,
        "channel": event.channel,
        "level": event.level,
        "computer_name": event.computer_name,
        "username": event.username,
        "source_ip": event.source_ip,
        "target_user": event.target_user,
        "target_host": event.target_host,
        "group_name": event.group_name,
        "logon_type": event.logon_type,
        "service_name": event.service_name,
        "message": event.message,
    }

    normalized = normalize_event(event)
    result = evaluate_event(event_dict=event_dict, normalized=normalized, recent_events=[])

    print(f"\n===== {name} =====")
    print("normalized =", normalized)
    print("result =", result)


if __name__ == "__main__":
    run_case("관리자 로그인 성공", "4624", "administrator", "administrator")
    run_case("일반 사용자 로그인 성공", "4624", "user1", "user1")
    run_case("관리자 로그오프", "4634", "administrator", "administrator")
    run_case("일반 사용자 로그오프", "4634", "user1", "user1")
    run_case("계정 생성", "4720", "administrator", "newuser")
    run_case("비밀번호 변경", "4723", "user1", "user1")
    run_case("비밀번호 재설정", "4724", "administrator", "user1")
    run_case("계정 비활성화", "4725", "administrator", "user1")
    run_case("계정 삭제", "4726", "administrator", "user1")
    run_case("Domain Admins 그룹 멤버 추가", "4728", "administrator", "user1", "Domain Admins")
    run_case("일반 글로벌 그룹 멤버 추가", "4728", "administrator", "user1", "Domain Users")
    run_case("Domain Admins 그룹 멤버 제거", "4729", "administrator", "user1", "Domain Admins")
    run_case("일반 글로벌 그룹 멤버 제거", "4729", "administrator", "user1", "Domain Users")
    run_case("Administrators 로컬 그룹 멤버 추가", "4732", "administrator", "user1", "Administrators")
    run_case("일반 로컬 그룹 멤버 추가", "4732", "administrator", "user1", "Remote Desktop Users")
    run_case("Administrators 로컬 그룹 멤버 제거", "4733", "administrator", "user1", "Administrators")
    run_case("일반 로컬 그룹 멤버 제거", "4733", "administrator", "user1", "Remote Desktop Users")
    run_case("Enterprise Admins 그룹 멤버 추가", "4756", "administrator", "user1", "Enterprise Admins")
    run_case("일반 유니버설 그룹 멤버 추가", "4756", "administrator", "user1", "Domain Users")
    run_case("Enterprise Admins 그룹 멤버 제거", "4757", "administrator", "user1", "Enterprise Admins")
    run_case("일반 유니버설 그룹 멤버 제거", "4757", "administrator", "user1", "Domain Users")