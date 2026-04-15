import os
import json
import requests
import streamlit as st
import pandas as pd

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
ATTACK_REQUESTED_BY = os.getenv("ATTACK_REQUESTED_BY", "")
VICTIM_URL = os.getenv("VICTIM_URL", "")

st.set_page_config(page_title="AD Log Dashboard", layout="wide")
st.title("AD 공격/방어 로그 대시보드")

if "last_run_id" not in st.session_state:
    st.session_state.last_run_id = None
if "last_scenario_id" not in st.session_state:
    st.session_state.last_scenario_id = None
if "last_target_ip" not in st.session_state:
    st.session_state.last_target_ip = None
if "last_requested_by" not in st.session_state:
    st.session_state.last_requested_by = None

tab_defense, tab_attack = st.tabs(["🛡️ 방어", "⚔️ 공격"])

with tab_defense:
    st.subheader("방어 모니터링")

    if st.button("이벤트 새로고침"):
        st.rerun()

    try:
        res = requests.get(f"{BACKEND_URL}/events?limit=100", timeout=5)
        res.raise_for_status()
        data = res.json()
    except Exception as e:
        st.error(f"백엔드 연결 실패: {e}")
        st.stop()

    if not data:
        st.info("수집된 이벤트가 없습니다.")
    else:
        df = pd.DataFrame(data)
        st.subheader("최근 이벤트")
        
        for idx, item in enumerate(data):
            try:
                event_json = json.loads(item.get("event_json") or "{}")
            except Exception:
                event_json = {}

            try:
                normalized = json.loads(item.get("normalized_json") or "{}")
            except Exception:
                normalized = {}

            try:
                detection = json.loads(item.get("detection_json") or "{}")
            except Exception:
                detection = {}

            try:
                risk = json.loads(item.get("risk_json") or "{}")
            except Exception:
                risk = {}

            try:
                raw_json = json.loads(item.get("raw_json") or "{}")
            except Exception:
                raw_json = item.get("raw_json")

            event_time = item.get("event_time", "-")
            event_id = item.get("event_id", "-")
            computer_name = item.get("computer_name", "-")
            username = item.get("username", "-")
            source_ip = item.get("source_ip", "-")
            group_name = item.get("group_name", "-")
            message = item.get("message", "-")

            event_type = normalized.get("event_type", "-")
            host_role = normalized.get("host_role", "-")
            account_type = normalized.get("account_type", "-")
            is_admin = normalized.get("is_admin_account", False)
            is_off_hours = normalized.get("is_off_hours", False)

            detected = detection.get("detected", False)
            rule_name = detection.get("rule_name", "-")
            attack_tactic = detection.get("attack_tactic", "-")

            severity = risk.get("severity", "none")
            final_score = risk.get("final_score", 0)

            with st.container(border=True):
                top1, top2, top3 = st.columns([4, 3, 3])

                with top1:
                    st.markdown(f"**{event_time}**")
                    st.write(f"이벤트 ID: `{event_id}`")
                    st.write(f"호스트: `{computer_name}`")
                    st.write(f"사용자: `{username}`")

                with top2:
                    st.write(f"이벤트 타입: **{event_type}**")
                    st.write(f"호스트 역할: **{host_role}**")
                    st.write(f"계정 유형: **{account_type}**")
                    st.write(f"관리자 계정 여부: **{is_admin}**")
                    st.write(f"업무 외 시간 여부: **{is_off_hours}**")

                with top3:
                    st.write(f"탐지 여부: **{detected}**")
                    st.write(f"탐지 룰: **{rule_name}**")
                    st.write(f"ATT&CK Tactic: **{attack_tactic}**")
                    st.write(f"위험도: **{severity}**")
                    st.write(f"점수: **{final_score}**")

                meta1, meta2 = st.columns(2)
                with meta1:
                    st.write(f"Source IP: `{source_ip}`")
                    st.write(f"Group: `{group_name}`")
                with meta2:
                    st.write(f"메시지: {message}")

                with st.expander("상세보기"):
                    st.markdown("**event_json**")
                    st.json(event_json)

                    st.markdown("**normalized_json**")
                    st.json(normalized)

                    st.markdown("**detection_json**")
                    st.json(detection)

                    st.markdown("**risk_json**")
                    st.json(risk)

                    st.markdown("**raw_json**")
                    st.json(raw_json if isinstance(raw_json, dict) else {"raw_text": raw_json})







        st.subheader("이벤트 요약")
        if "event_id" in df.columns:
            st.write(df["event_id"].value_counts().head(10))

with tab_attack:
    st.subheader("최근 실행 이력")

    st.button("실행 이력 새로고침", key="refresh_history")

    try:
        history_res = requests.get(f"{BACKEND_URL}/scenario-runs?limit=5", timeout=5)
        history_res.raise_for_status()
        history_data = history_res.json()
    except Exception as e:
        st.error(f"실행 이력 조회 실패: {e}")
        history_data = []

    if isinstance(history_data, dict) and history_data.get("result") == "error":
        st.error(history_data.get("message"))
    else:
        if not history_data:
            st.info("최근 실행 이력이 없습니다.")
        else:
            history_rows = []
            for item in history_data:
                raw_status = item.get("status", "-")

                if raw_status == "running":
                    display_status = "🟢 running"
                elif raw_status == "success":
                    display_status = "✅ success"
                elif raw_status == "failed":
                    display_status = "❌ failed"
                else:
                    display_status = raw_status

                history_rows.append({
                    "run_id": item.get("run_id", "-"),
                    "실행자": item.get("requested_by", "-"),
                    "시나리오": item.get("scenario_id", "-"),
                    "타겟 IP": item.get("target_ip", "-"),
                    "상태": display_status,
                    "시작 시간": item.get("started_at", "-"),
                })

            history_df = pd.DataFrame(history_rows)
            def highlight_status(val):
                if "running" in str(val):
                    return "background-color: #FFC19E; color: #6F310E; font-weight: bold;"
                elif "success" in str(val):
                    return "background-color: #ecfdf5; color: #166534;"
                elif "failed" in str(val):
                    return "background-color: #fef2f2; color: #991b1b;"
                return ""

            styled_df = history_df.style.map(
                highlight_status,
                subset=["상태"]
            )

            st.dataframe(styled_df, use_container_width=True)

    st.divider()
    st.subheader("공격 시나리오 실행")

    col_target, col_user = st.columns([6, 4])
    with col_target:
        target_ip = st.text_input("대상 IP", value=VICTIM_URL)
    with col_user:
        requested_by = st.text_input("실행자", value=ATTACK_REQUESTED_BY)

    try:
        res = requests.get(f"{BACKEND_URL}/scenario/list", timeout=5)
        res.raise_for_status()
        scenarios = res.json()
    except Exception as e:
        st.error(f"시나리오 목록 조회 실패: {e}")
        st.stop()

    st.markdown("### 시나리오 목록")

    if isinstance(scenarios, dict) and scenarios.get("result") == "error":
        st.error(scenarios.get("message"))
    else:
        for scenario in scenarios:
            with st.container(border=True):
                c1, c2 = st.columns([8, 2])

                with c1:
                    st.markdown(f"**{scenario['label']}**")

                with c2:
                    if st.button("실행", key=f"run_{scenario['scenario_id']}"):
                        if not target_ip.strip():
                            st.warning("타겟 IP를 입력하세요.")
                        elif not requested_by.strip():
                            st.warning("실행자를 입력하세요.")
                        else:
                            try:
                                run_res = requests.post(
                                    f"{BACKEND_URL}/scenario/run",
                                    json={
                                        "scenario_id": scenario["scenario_id"],
                                        "params": {
                                            "target_ip": target_ip.strip(),
                                            "requested_by": requested_by.strip()
                                        }
                                    },
                                    timeout=10
                                )
                                run_res.raise_for_status()
                                result = run_res.json()

                                if result.get("result") == "error":
                                    st.warning(result.get("message", "시나리오 실행이 거부되었습니다."))
                                else:
                                    st.session_state.last_run_id = result.get("run_id")
                                    st.session_state.last_scenario_id = result.get("scenario_id")
                                    st.session_state.last_target_ip = target_ip.strip()
                                    st.session_state.last_requested_by = requested_by.strip()
                                    st.success(f"{scenario['label']} 실행 요청 완료")
                            except Exception as e:
                                st.error(f"시나리오 실행 실패: {e}")


    st.divider()
    st.subheader("마지막 실행 상태")

    if st.session_state.last_run_id:
        st.write(f"run_id: {st.session_state.last_run_id}")

        if st.button("상태 새로고침"):
            try:
                status_res = requests.get(
                    f"{BACKEND_URL}/scenario/status/{st.session_state.last_run_id}",
                    timeout=5
                )
                status_res.raise_for_status()
                status_data = status_res.json()

                status = status_data.get("status", "unknown")
                scenario_id = status_data.get("scenario_id", "-")
                target_ip_status = status_data.get("target_ip", st.session_state.get("last_target_ip", "-"))
                requested_by_status = status_data.get("requested_by", st.session_state.get("last_requested_by", "-"))
                started_at = status_data.get("started_at", "-")
                finished_at = status_data.get("finished_at", "-")
                return_code = status_data.get("return_code", "-")
                log_path = status_data.get("log_path", "-")

                machine_status = "사용 중" if status == "running" else "대기 중"

                if status == "running":
                    st.warning(f"현재 공격머신 상태: {machine_status}")
                elif status == "success":
                    st.success("실행 성공")
                elif status == "failed":
                    st.error("실행 실패")
                else:
                    st.info(f"상태: {status}")

                top1, top2, top3, top4 = st.columns(4)
                top1.metric("시나리오", scenario_id)
                top2.metric("상태", status)
                top3.metric("반환 코드", return_code if return_code is not None else "-")
                top4.metric("공격머신 상태", machine_status)

                c1, c2 = st.columns(2)
                with c1:
                    st.write(f"**실행자**: {requested_by_status}")
                    st.write(f"**타겟 IP**: {target_ip_status}")
                    st.write(f"**시작 시간**: {started_at}")

                with c2:
                    st.write(f"**종료 시간**: {finished_at}")
                    st.write(f"**로그 경로**: `{log_path}`")

                with st.expander("원본 상태 JSON 보기"):
                    st.json(status_data)

            except Exception as e:
                st.error(f"상태 조회 실패: {e}")
    else:
        st.info("아직 실행한 시나리오가 없습니다.")