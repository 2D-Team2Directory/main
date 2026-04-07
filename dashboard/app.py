import os
import requests
import streamlit as st
import pandas as pd

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

st.set_page_config(page_title="AD Log Dashboard", layout="wide")
st.title("AD 공격/방어 로그 대시보드")

if st.button("새로고침"):
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