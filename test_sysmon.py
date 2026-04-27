from analysis.detection_engine import evaluate_event


def run_case(name, image, query_name):
    event_dict = {
        "event_time": "2026-04-23T16:00:00Z",
        "event_id": "22",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "level": "information",
        "computer_name": "CLIENT-01",
        "username": "administrator",
        "source_ip": None,
        "target_user": "administrator",
        "target_host": None,
        "group_name": None,
        "logon_type": None,
        "service_name": None,
        "message": "DNS Query",
        "image": image,
        "command_line": None,
        "parent_image": None,
        "parent_command_line": None,
        "current_directory": None,
        "user": "administrator",
        "destination_ip": None,
        "destination_port": None,
        "source_port": None,
        "protocol": None,
        "image_loaded": None,
        "signed": None,
        "signature_status": None,
        "hashes": None,
        "target_filename": None,
        "creation_utc_time": None,
        "target_object": None,
        "registry_event_type": None,
        "details": None,
        "query_name": query_name,
        "query_status": "0",
        "query_results": "1.2.3.4",
    }

    normalized = {
        "event_type": "dns_query",
        "is_admin_account": True,
        "is_off_hours": False,
    }

    result = evaluate_event(
        event_dict=event_dict,
        normalized=normalized,
        recent_events=[]
    )

    print(f"\n===== {name} =====")
    print("event_dict =", event_dict)
    print("result =", result)


if __name__ == "__main__":
    run_case(
        "의심 powershell github DNS 질의",
        "powershell.exe",
        "raw.githubusercontent.com"
    )

    run_case(
        "의심 certutil .xyz DNS 질의",
        "certutil.exe",
        "evil-update.xyz"
    )

    run_case(
        "정상 notepad github DNS 질의",
        "notepad.exe",
        "github.com"
    )

    run_case(
        "의심 powershell 일반 내부 DNS 질의",
        "powershell.exe",
        "intranet.local"
    )