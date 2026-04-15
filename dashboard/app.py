import os
import requests
import streamlit as st
import pandas as pd

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

st.set_page_config(page_title="AD Log Dashboard", layout="wide")
st.title("AD 공격/방어 로그 대시보드")

if "last_run_id" not in st.session_state:
    st.session_state.last_run_id = None
if "last_scenario_id" not in st.session_state:
    st.session_state.last_scenario_id = None

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
        st.dataframe(df, use_container_width=True)

        st.subheader("이벤트 요약")
        if "event_id" in df.columns:
            st.write(df["event_id"].value_counts().head(10))

with tab_attack:
    st.subheader("공격 시나리오 실행")

    try:
        res = requests.get(f"{BACKEND_URL}/scenario/list", timeout=5)
        res.raise_for_status()
        scenarios = res.json()
    except Exception as e:
        st.error(f"시나리오 목록 조회 실패: {e}")
        # st.stop()

    if isinstance(scenarios, dict) and scenarios.get("result") == "error":
        st.error(scenarios.get("message"))
    else:
        for scenario in scenarios:
            c1, c2 = st.columns([4, 1])

            with c1:
                st.markdown(f"**{scenario['label']}**")
                st.write(scenario.get("description", ""))

            with c2:
                if st.button("실행", key=f"run_{scenario['scenario_id']}"):
                    try:
                        run_res = requests.post(
                            f"{BACKEND_URL}/scenario/run",
                            json={"scenario_id": scenario["scenario_id"]},
                            timeout=10
                        )
                        run_res.raise_for_status()
                        result = run_res.json()

                        st.session_state.last_run_id = result.get("run_id")
                        st.session_state.last_scenario_id = result.get("scenario_id")

                        st.success(f"실행 요청 완료: {result}")
                    except Exception as e:
                        st.error(f"시나리오 실행 실패: {e}")

    st.divider()
    st.subheader("마지막 실행 상태")

    if st.session_state.last_run_id:
        st.write(f"run_id: {st.session_state.last_run_id}")
        st.write(f"scenario_id: {st.session_state.last_scenario_id}")

        if st.button("상태 새로고침"):
            try:
                status_res = requests.get(
                    f"{BACKEND_URL}/scenario/status/{st.session_state.last_run_id}",
                    timeout=5
                )
                status_res.raise_for_status()
                status_data = status_res.json()

                status = status_data.get("status", "unknown")
                run_id = status_data.get("run_id", "-")
                scenario_id = status_data.get("scenario_id", "-")
                started_at = status_data.get("started_at", "-")
                finished_at = status_data.get("finished_at", "-")
                return_code = status_data.get("return_code", "-")
                log_path = status_data.get("log_path", "-")

                # 상태별 표시 문구
                if status == "success":
                    st.success("실행 성공")
                elif status == "failed":
                    st.error("실행 실패")
                elif status == "running":
                    st.warning("실행 중")
                else:
                    st.info(f"상태: {status}")

                c1, c2, c3 = st.columns(3)
                c1.metric("시나리오", scenario_id)
                c2.metric("상태", status)
                c3.metric("반환 코드", return_code if return_code is not None else "-")

                c4, c5 = st.columns(2)
                with c4:
                    st.write(f"**run_id**: {run_id}")
                    st.write(f"**시작 시간**: {started_at}")
                with c5:
                    st.write(f"**종료 시간**: {finished_at}")
                    st.write(f"**로그 경로**: `{log_path}`")

                with st.expander("원본 상태 JSON 보기"):
                    st.json(status_data)
            except Exception as e:
                st.error(f"상태 조회 실패: {e}")
    else:
        st.info("아직 실행한 시나리오가 없습니다.")