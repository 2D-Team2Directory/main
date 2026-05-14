"""
정찰 종합 리포트 페이지

PowerView, PingCastle, BloodHound 의 최신 결과를 하나의 HTML 리포트로 통합한다.

- 백엔드의 /recon-results/latest/{tool} 와 /recon-results/latest/{tool}/summary 를 사용
- BloodHound 는 /data/bloodhound/<컬렉션>/graph.html 직접 임베드
- 브라우저 인쇄(Ctrl+P) → PDF 저장 가능하도록 인쇄용 CSS 포함
"""

import json
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from api_client import get_latest_recon_summary, get_latest_recon_result
from components import severity_badge, SEVERITY_ORDER


PINGCASTLE_LATEST_DIR = "/data/recon/pingcastle/latest"
BLOODHOUND_ROOT = "/data/bloodhound"


# ------------------------------------------------------------------
# 위험도 평가 임계값
# ------------------------------------------------------------------
RISK_THRESHOLDS = [
    # (key, label, medium_threshold, high_threshold, description)
    ("spn_users_count", "SPN 계정 수", 1, 5,
     "SPN이 설정된 사용자 계정은 Kerberoasting 공격 대상이 됩니다."),
    ("no_preauth_users_count", "Kerberos PreAuth 비활성 계정", 1, 3,
     "Pre-authentication 이 꺼진 계정은 AS-REP Roasting 공격 대상이 됩니다."),
    ("interesting_acls_count", "Interesting ACL", 1, 5,
     "민감한 ACL 권한이 설정된 객체는 권한 상승 경로가 될 수 있습니다."),
    ("domain_admins_count", "Domain Admins 수", 5, 10,
     "도메인 관리자 계정 수가 많을수록 침해 시 영향 범위가 커집니다."),
    ("enterprise_admins_count", "Enterprise Admins 수", 1, 3,
     "Enterprise Admins 는 포레스트 전역에 영향을 미치므로 최소화해야 합니다."),
    ("dns_admins_count", "DnsAdmins 수", 1, 3,
     "DnsAdmins 는 DC 권한 상승에 악용될 수 있는 경로입니다."),
]


# README 방어 시나리오 매핑 (PowerView 위험 항목 → 권고사항)
RECOMMENDATION_MAP = {
    "spn_users_count": [
        "서비스 계정 비밀번호 복잡도 강화 및 주기적 변경",
        "AES 암호화만 허용하도록 GPO 설정",
        "Kerberos 티켓 요청 급증 탐지 룰 적용",
    ],
    "no_preauth_users_count": [
        "사용자 계정의 'Do not require Kerberos preauthentication' 옵션 해제",
        "AS-REP 로깅 활성화 및 비정상 요청 알림",
    ],
    "interesting_acls_count": [
        "민감 객체에 대한 ACL 정기 감사",
        "GPO 기반 감사 정책 강화",
        "특권 계정 사용시 알림",
    ],
    "domain_admins_count": [
        "관리자 계정 사용 제한 및 분리",
        "관리자 그룹 변경 감시",
        "Tier 0 자산 접근 통제",
    ],
    "enterprise_admins_count": [
        "Enterprise Admins 그룹은 비워두고 필요시에만 임시 부여",
        "특권 계정 사용 이벤트 알림",
    ],
    "dns_admins_count": [
        "DnsAdmins 멤버 최소화",
        "비정상 시간대 로그인 탐지",
    ],
}


# PowerView 위험 항목 → 가능한 공격 시나리오 매핑
ATTACK_SCENARIO_MAP = {
    "spn_users_count": [
        ("Kerberoasting", "high",
         "SPN 등록 계정의 TGS를 요청해 오프라인에서 비밀번호를 크래킹"),
    ],
    "no_preauth_users_count": [
        ("AS-REP Roasting", "high",
         "Pre-Auth 비활성 계정에 AS-REQ를 보내 암호화된 응답을 받아 크래킹"),
    ],
    "interesting_acls_count": [
        ("ACL 기반 권한 상승", "high",
         "WriteDACL/GenericAll 등 위험 권한을 이용해 대상 객체 제어권 확보"),
        ("Shadow Credentials", "medium",
         "msDS-KeyCredentialLink 속성 변조로 인증서 기반 권한 상승"),
    ],
    "domain_admins_count": [
        ("내부 이동 / 관리자 권한 탈취", "high",
         "Domain Admins 계정이 많을수록 한 명만 침해돼도 전체 도메인 통제 가능"),
        ("Pass-the-Hash / Ticket", "medium",
         "관리자 NTLM 해시 또는 TGT 재사용으로 다른 호스트 접근"),
    ],
    "enterprise_admins_count": [
        ("포레스트 전역 권한 탈취", "critical",
         "Enterprise Admins 침해 시 모든 도메인에 영향, 포레스트 신뢰 관계 악용 가능"),
    ],
    "dns_admins_count": [
        ("DnsAdmins DLL Injection", "high",
         "dnscmd로 악성 DLL 로드 → DC 권한 상승 (T1574)"),
    ],
}


# PingCastle 일반 권고사항 (HealthCheck 점수/항목 기반)
PINGCASTLE_RECOMMENDATIONS = [
    ("Stale Object",
     [
         "오랫동안 사용되지 않은 계정/컴퓨터 객체 비활성화 및 정리",
         "LAPS(Local Admin Password Solution) 도입으로 로컬 관리자 암호 자동 회전",
         "krbtgt 계정 비밀번호 주기적 재설정 (12개월 이내 권장)",
     ]),
    ("Privileged Account",
     [
         "Domain Admins / Enterprise Admins 그룹 최소화 및 분리",
         "관리자 전용 워크스테이션(PAW) 사용 강제",
         "Protected Users 보안 그룹 활용",
     ]),
    ("Trust 관계",
     [
         "불필요한 도메인 신뢰 관계 제거",
         "SID Filtering / Selective Authentication 활성화",
     ]),
    ("Anomalies (이상 설정)",
     [
         "Pre-Authentication 비활성 옵션이 켜진 계정 점검 및 해제",
         "Reversible Encryption 옵션 사용 계정 점검",
         "Unconstrained Delegation 컴퓨터 점검 및 제한",
     ]),
    ("정책/감사 강화",
     [
         "GPO를 통한 감사 정책(Audit Policy) 강화",
         "LLMNR / NetBIOS-NS / WPAD 비활성화로 응답자(Responder) 공격 차단",
         "SMB Signing 강제 및 SMBv1 비활성화",
         "비정상 시간대 / 다중 호스트 동시 로그인 알림 룰 적용",
     ]),
]


# ------------------------------------------------------------------
# 유틸
# ------------------------------------------------------------------

def _evaluate_severity(value: int, medium_th: int, high_th: int) -> str:
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        value = 0

    if value >= high_th:
        return "high"
    if value >= medium_th:
        return "medium"
    if value > 0:
        return "low"
    return "none"


def _safe_get_summary(tool: str) -> dict:
    try:
        summary = get_latest_recon_summary(tool)
    except Exception as e:
        return {"result": "error", "message": str(e), "tool": tool}

    if not isinstance(summary, dict):
        return {"result": "error", "message": "summary 형식 오류", "tool": tool}

    return summary


def _safe_get_result(tool: str) -> dict:
    try:
        result = get_latest_recon_result(tool)
    except Exception as e:
        return {"result": "error", "message": str(e), "tool": tool}

    if not isinstance(result, dict):
        return {"result": "error", "message": "result 형식 오류", "tool": tool}

    return result


def _summary_available(summary: dict) -> bool:
    return summary.get("result") not in ("empty", "error") and summary


def _get_powerview_detail_items(pv_result: dict, key: str):
    """PowerView result.json의 상세 목록을 top-level 또는 data 내부에서 안전하게 꺼낸다."""
    if not isinstance(pv_result, dict):
        return None

    direct = pv_result.get(key)
    if direct:
        return direct

    data = pv_result.get("data")
    if isinstance(data, dict):
        return data.get(key)

    return None


def _list_bloodhound_collections():
    if not os.path.isdir(BLOODHOUND_ROOT):
        return []
    dirs = sorted(
        [d for d in Path(BLOODHOUND_ROOT).iterdir() if d.is_dir()],
        reverse=True,
    )
    return [(d.name, d / "graph.html") for d in dirs if (d / "graph.html").exists()]


def _extract_report_defaults(pv_summary: dict, pv_result: dict, pc_summary: dict) -> dict:
    """
    최신 정찰 결과에서 리포트 표지용 기본값을 추출한다.
    사용자가 직접 수정할 수 있도록 text_input의 기본값으로만 사용한다.
    """

    pv_data = pv_result if isinstance(pv_result, dict) else {}
    pc_data = pc_summary if isinstance(pc_summary, dict) else {}

    # PowerView result.json 우선, 없으면 PingCastle summary 사용
    domain = (
        pv_data.get("domain")
        or pc_data.get("domain")
        or st.session_state.get("report_domain")
        or "lab.local"
    )

    target_ip = (
        pv_data.get("target_host")
        or pc_data.get("target_ip")
        or st.session_state.get("last_target_ip")
        or st.session_state.get("report_target_ip")
        or ""
    )

    requested_by = (
        pv_data.get("requested_by")
        or st.session_state.get("last_requested_by")
        or st.session_state.get("report_requested_by")
        or ""
    )

    return {
        "domain": str(domain or ""),
        "target_ip": str(target_ip or ""),
        "requested_by": str(requested_by or ""),
    }


# ------------------------------------------------------------------
# 인쇄용 CSS / 표지
# ------------------------------------------------------------------
def _inject_print_css():
    st.markdown(
        """
        <style>
        @media print {
            /* 사이드바, 헤더 등 인쇄 시 숨김 */
            section[data-testid="stSidebar"],
            header[data-testid="stHeader"],
            div[data-testid="stToolbar"] {
                display: none !important;
            }
            .stApp {
                background: #ffffff !important;
            }
            .recon-report-cover {
                page-break-after: always;
            }
            .report-section {
                page-break-inside: avoid;
            }
        }
        .recon-report-cover {
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 32px 28px;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%);
        }
        .recon-report-cover h1 {
            margin: 0 0 12px 0;
            font-size: 1.8rem;
        }
        .recon-report-cover .meta {
            color: #374151;
            font-size: 0.95rem;
            line-height: 1.7;
        }
        .report-section h3 {
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 6px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_cover(domain: str, target_ip: str, requested_by: str):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(
        f"""
        <div class="recon-report-cover">
            <h1>AD 정찰 종합 리포트</h1>
            <div class="meta">
                <div>도메인 : <b>{domain or '-'}</b></div>
                <div>대상 IP : <b>{target_ip or '-'}</b></div>
                <div>생성 일시 : <b>{generated_at}</b></div>
                <div>실행자 : <b>{requested_by or '-'}</b></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------------
# Executive Summary
# ------------------------------------------------------------------
def _risk_count(risk_rows: list[dict], severity: str) -> int:
    return sum(1 for row in risk_rows if row.get("등급") == severity)


def _to_int(value, default=0) -> int:
    try:
        if value is None or value == "-":
            return default
        return int(value)
    except Exception:
        return default


def _evaluate_pingcastle_severity(score: int) -> str:
    """PingCastle 점수는 낮을수록 양호하므로 점수 구간으로 위험도를 표현한다."""
    score = _to_int(score, 0)

    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _pingcastle_threshold_text(severity: str) -> str:
    if severity == "high":
        return "80점 이상"
    if severity == "medium":
        return "50점 이상"
    if severity == "low":
        return "1점 이상"
    return "0점"


def _render_tool_status_card(title: str, body_html: str, caption: str = ""):
    with st.container(border=True):
        st.markdown(f"**{title}**")
        st.markdown(body_html, unsafe_allow_html=True)
        if caption:
            st.caption(caption)


def _render_executive_summary(pv_summary, pc_summary, bh_collections, risk_rows, overall):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 1. Executive Summary")

    s1, s2, s3 = st.columns(3)

    with s1:
        if _summary_available(pv_summary):
            high_or_more_count = (
                _risk_count(risk_rows, "critical")
                + _risk_count(risk_rows, "high")
            )
            medium_count = _risk_count(risk_rows, "medium")
            _render_tool_status_card(
                "PowerView",
                f"위험 평가 {severity_badge(overall)}",
                f"2-2 위험 항목 평가 기준 · HIGH 이상 {high_or_more_count}개 / MEDIUM {medium_count}개",
            )
        else:
            _render_tool_status_card(
                "PowerView",
                severity_badge("none"),
                "저장된 PowerView 결과가 없습니다.",
            )

    with s2:
        if _summary_available(pc_summary):
            pc_score = _to_int(pc_summary.get("global_score"), 0)
            pc_severity = _evaluate_pingcastle_severity(pc_score)
            _render_tool_status_card(
                "PingCastle",
                f"위험도 점수 {severity_badge(pc_severity)}",
                f"Global Score {pc_score}점 · {pc_severity.upper()} 기준: {_pingcastle_threshold_text(pc_severity)}",
            )
        else:
            _render_tool_status_card(
                "PingCastle",
                severity_badge("none"),
                "저장된 PingCastle 결과가 없습니다.",
            )

    with s3:
        if bh_collections:
            _render_tool_status_card(
                "BloodHound",
                "<b>수집됨</b>",
                f"graph.html 포함 컬렉션 {len(bh_collections)}개",
            )
        else:
            _render_tool_status_card(
                "BloodHound",
                "<b>없음</b>",
                "graph.html이 포함된 컬렉션이 없습니다.",
            )

    # st.caption(
    #     "PowerView는 본문 2-2 위험 항목 평가의 최고 등급을 요약하고, "
    #     "PingCastle은 Global Score 기준으로 위험도를 구간화합니다. "
    #     "BloodHound는 그래프 컬렉션 수집 여부만 표시합니다."
    # )

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# 위험 평가
# ------------------------------------------------------------------
def _compute_risks(pv_summary: dict):
    """위험 항목 평가 결과 리스트와 전체 등급 반환"""
    rows = []
    overall = "none"

    if not _summary_available(pv_summary):
        return rows, overall

    for key, label, mid, high, desc in RISK_THRESHOLDS:
        value = pv_summary.get(key, 0)
        try:
            value_int = int(value or 0)
        except (TypeError, ValueError):
            value_int = 0

        severity = _evaluate_severity(value_int, mid, high)
        rows.append({
            "key": key,
            "항목": label,
            "값": value_int,
            "등급": severity,
            "설명": desc,
        })

        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[overall]:
            overall = severity

    return rows, overall


# ------------------------------------------------------------------
# PowerView 종합 (위험 평가 + 메트릭 + 상세 + 추천 공격 시나리오)
# ------------------------------------------------------------------
def _render_attack_scenarios(risk_rows):
    """위험 등급이 있는 항목을 기반으로 주의해야 할 공격 시나리오 출력"""
    triggered = [r for r in risk_rows
                 if SEVERITY_ORDER.get(r["등급"], 0) >= SEVERITY_ORDER["low"]]

    if not triggered:
        st.success("현재 결과 기준으로 즉시 주의가 필요한 공격 시나리오는 없습니다.")
        return

    # 항목별 매핑된 시나리오 수집
    seen = set()
    scenarios = []
    for r in triggered:
        for name, sev, desc in ATTACK_SCENARIO_MAP.get(r["key"], []):
            if name in seen:
                continue
            seen.add(name)
            scenarios.append({
                "name": name,
                "severity": sev,
                "desc": desc,
                "source": r["항목"],
                "source_value": r["값"],
            })

    if not scenarios:
        st.info("매핑된 공격 시나리오가 없습니다.")
        return

    # 심각도 순 정렬
    scenarios.sort(key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0))

    table_html = """
    <table style="width:100%; border-collapse:collapse; margin-top:10px;">
        <thead>
            <tr style="background:#fef2f2;">
                <th style="padding:8px; border:1px solid #fecaca; text-align:left;">공격 시나리오</th>
                <th style="padding:8px; border:1px solid #fecaca; text-align:center;">위험도</th>
                <th style="padding:8px; border:1px solid #fecaca; text-align:left;">유발 조건</th>
                <th style="padding:8px; border:1px solid #fecaca; text-align:left;">설명</th>
            </tr>
        </thead>
        <tbody>
    """
    for s in scenarios:
        table_html += (
            "<tr>"
            f"<td style='padding:8px; border:1px solid #fecaca;'><b>{s['name']}</b></td>"
            f"<td style='padding:8px; border:1px solid #fecaca; text-align:center;'>{severity_badge(s['severity'])}</td>"
            f"<td style='padding:8px; border:1px solid #fecaca; color:#374151;'>{s['source']} = {s['source_value']}</td>"
            f"<td style='padding:8px; border:1px solid #fecaca; color:#374151;'>{s['desc']}</td>"
            "</tr>"
        )
    table_html += "</tbody></table>"

    st.markdown(table_html, unsafe_allow_html=True)


def _render_powerview_combined(pv_summary, pv_result, risk_rows, overall):
    """PowerView 위험 평가 + 메트릭 + 상세 + 추천 공격 시나리오를 하나로"""
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 2. PowerView 종합")

    if not _summary_available(pv_summary):
        st.info("PowerView 결과가 없습니다.")
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown("")
        return

    # --- 2-1. 자산 메트릭
    # 2-2 위험 항목 평가에 포함되는 SPN/NoPreAuth/관리자 그룹/ACL 수치는 제외하고,
    # 순수 자산 규모와 수집 범위만 표시한다.
    st.markdown("#### 2-1. 자산 현황")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("총 사용자", pv_summary.get("total_users", 0))
    c2.metric("총 그룹", pv_summary.get("total_groups", 0))
    c3.metric("총 컴퓨터", pv_summary.get("total_computers", 0))
    c4.metric("OU", pv_summary.get("ous_count", 0))
    c5.metric("Trust", pv_summary.get("trusts_count", 0))

    st.caption(
        "2-1은 AD 객체 규모와 수집 범위만 보여줍니다. "
        "SPN, NoPreAuth, 관리자 그룹, Interesting ACL처럼 위험도 판단에 쓰이는 항목은 2-2에서만 평가합니다."
    )

    # --- 2-2. 위험 항목 평가
    st.markdown("#### 2-2. 위험 항목 평가")

    if not risk_rows:
        st.info("평가 가능한 항목이 없습니다.")
    else:
        st.markdown(
            f"전체 위험 등급 : {severity_badge(overall)}",
            unsafe_allow_html=True,
        )

        table_html = """
        <table style="width:100%; border-collapse:collapse; margin-top:10px;">
            <thead>
                <tr style="background:#f9fafb;">
                    <th style="padding:8px; border:1px solid #e5e7eb; text-align:left;">항목</th>
                    <th style="padding:8px; border:1px solid #e5e7eb; text-align:right;">값</th>
                    <th style="padding:8px; border:1px solid #e5e7eb; text-align:center;">등급</th>
                    <th style="padding:8px; border:1px solid #e5e7eb; text-align:left;">설명</th>
                </tr>
            </thead>
            <tbody>
        """
        for r in risk_rows:
            table_html += (
                "<tr>"
                f"<td style='padding:8px; border:1px solid #e5e7eb;'>{r['항목']}</td>"
                f"<td style='padding:8px; border:1px solid #e5e7eb; text-align:right;'>{r['값']}</td>"
                f"<td style='padding:8px; border:1px solid #e5e7eb; text-align:center;'>{severity_badge(r['등급'])}</td>"
                f"<td style='padding:8px; border:1px solid #e5e7eb; color:#374151;'>{r['설명']}</td>"
                "</tr>"
            )
        table_html += "</tbody></table>"
        st.markdown(table_html, unsafe_allow_html=True)

    # --- 2-3. 추천/주의 공격 시나리오
    st.markdown("#### 2-3. 주의해야 할 공격 시나리오")
    st.caption("위험 항목 평가 결과를 바탕으로 우선 점검이 권장되는 공격 시나리오입니다.")
    _render_attack_scenarios(risk_rows)

    # --- 2-4. 상세 목록 (있는 경우만)
    detail_keys = [
        ("domain_admins", "Domain Admins 목록"),
        ("enterprise_admins", "Enterprise Admins 목록"),
        ("dns_admins", "DnsAdmins 목록"),
        ("spn_users", "SPN 계정 목록"),
        ("no_preauth_users", "NoPreAuth 계정 목록"),
        ("interesting_acls", "Interesting ACLs 목록"),
    ]
    detail_items = [(k, t) for k, t in detail_keys
                    if _get_powerview_detail_items(pv_result, k)]

    if detail_items:
        st.markdown("#### 2-4. 상세 목록")
        for key, title in detail_items:
            items = _get_powerview_detail_items(pv_result, key)
            with st.expander(f"{title} ({len(items)})", expanded=False):
                try:
                    if isinstance(items[0], dict):
                        st.dataframe(pd.DataFrame(items), use_container_width=True, hide_index=True)
                    else:
                        st.write(items)
                except Exception:
                    st.json(items)

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# PingCastle 상세
# ------------------------------------------------------------------
def _render_pingcastle_combined(pc_summary, pc_result):
    """PingCastle 점수/리스크 요약 + HTML 임베드 + 점검/정책개선/권고사항"""
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 3. PingCastle 종합")

    if not _summary_available(pc_summary):
        st.info("PingCastle 결과가 없습니다.")
        # 결과가 없어도 일반 권고사항은 보여주기
        st.markdown("#### 일반 점검 / 정책 개선 권고")
        for category, recs in PINGCASTLE_RECOMMENDATIONS:
            with st.container(border=True):
                st.markdown(f"**{category}**")
                for rec in recs:
                    st.markdown(f"- {rec}")
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown("")
        return

    # --- 3-1. 점수 / 상태 요약
    st.markdown("#### 3-1. 점수 / 상태 요약")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("도메인", pc_summary.get("domain", "-"))
    m2.metric("대상", pc_summary.get("target_ip", "-"))
    m3.metric("상태", pc_summary.get("status", "-"))
    m4.metric("XML 생성", "OK" if pc_summary.get("xml_generated") else "-")

    # 선택적으로 PingCastle 점수 필드가 summary에 들어있다면 표시
    score_keys = [
        ("global_score", "전체 점수"),
        ("stale_object_score", "Stale Object"),
        ("privileged_group_score", "Privileged Group"),
        ("trust_score", "Trust"),
        ("anomaly_score", "Anomalies"),
    ]
    score_items = [(k, t) for k, t in score_keys if pc_summary.get(k) is not None]
    if score_items:
        st.markdown("**리스크 점수 (낮을수록 좋음)**")
        cols = st.columns(len(score_items))
        for col, (k, t) in zip(cols, score_items):
            col.metric(t, pc_summary.get(k))

    # --- 3-2. HealthCheck HTML 보고서
    html_name = pc_summary.get("html_report")
    html_path = None
    if html_name:
        candidate = Path(PINGCASTLE_LATEST_DIR) / html_name
        if candidate.exists():
            html_path = candidate

    if html_path:
        st.markdown("#### 3-2. HealthCheck HTML 보고서")
        height = st.slider(
            "PingCastle 보고서 높이 (px)",
            min_value=500, max_value=1400, value=900, step=100,
            key="report_pingcastle_height",
        )
        try:
            html_content = html_path.read_text(encoding="utf-8", errors="replace")
            components.html(html_content, height=height, scrolling=True)
        except Exception as e:
            st.error(f"PingCastle HTML 로드 실패: {e}")
    else:
        st.markdown("#### 3-2. HealthCheck HTML 보고서")
        st.info("HTML 보고서 파일을 찾을 수 없습니다.")

    # --- 3-3. 보고서 원본 파일 다운로드
    artifacts = []
    if isinstance(pc_summary.get("artifacts"), list):
        artifacts = pc_summary["artifacts"]
    elif isinstance(pc_result, dict) and isinstance(pc_result.get("saved_artifacts"), list):
        artifacts = pc_result["saved_artifacts"]

    if artifacts:
        st.markdown("#### 3-3. 보고서 원본 파일")
        for artifact in artifacts:
            filename = artifact.get("filename")
            latest_path = artifact.get("latest_path")
            mime_type = artifact.get("mime_type", "application/octet-stream")
            if not latest_path or not os.path.exists(latest_path):
                continue
            try:
                with open(latest_path, "rb") as f:
                    st.download_button(
                        label=f"⬇ {filename} 다운로드",
                        data=f,
                        file_name=filename,
                        mime=mime_type,
                        key=f"report_pc_dl_{filename}",
                    )
            except Exception as e:
                st.error(f"{filename} 다운로드 준비 실패: {e}")

    # --- 3-4. 점검 / 정책 개선 / 권고사항
    st.markdown("#### 3-4. 점검 / 정책 개선 / 권고사항")
    st.caption("PingCastle 결과 카테고리별 일반 권고사항입니다. HTML 보고서 상세와 함께 검토하세요.")
    for category, recs in PINGCASTLE_RECOMMENDATIONS:
        with st.container(border=True):
            st.markdown(f"**{category}**")
            for rec in recs:
                st.markdown(f"- {rec}")

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# BloodHound 상세
# ------------------------------------------------------------------
def _render_bloodhound_section(collections):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 4. BloodHound 그래프")

    if not collections:
        st.info(f"`{BLOODHOUND_ROOT}` 에 graph.html 이 포함된 컬렉션이 없습니다.")
        st.markdown('</div>', unsafe_allow_html=True)
        return

    names = [name for name, _ in collections]
    selected = st.selectbox(
        "리포트에 포함할 컬렉션",
        names,
        index=0,
        key="report_bh_collection",
    )
    selected_path = next(path for name, path in collections if name == selected)

    height = st.slider(
        "BloodHound 그래프 높이 (px)",
        min_value=400, max_value=1200, value=700, step=50,
        key="report_bh_height",
    )

    try:
        html_content = selected_path.read_text(encoding="utf-8")
        components.html(html_content, height=height, scrolling=True)
    except Exception as e:
        st.error(f"BloodHound 그래프 로드 실패: {e}")

    try:
        with open(selected_path, "rb") as f:
            st.download_button(
                label="⬇ BloodHound graph.html 다운로드",
                data=f,
                file_name=f"{selected}_graph.html",
                mime="text/html",
                key=f"report_bh_dl_{selected}",
            )
    except Exception:
        pass

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# 부록 (원본 데이터)
# ------------------------------------------------------------------
def _render_appendix(pv_result, pc_result):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 5. 부록 - 원본 데이터")

    with st.expander("PowerView result.json", expanded=False):
        if _summary_available(pv_result):
            st.json(pv_result)
        else:
            st.info("데이터 없음")

    with st.expander("PingCastle result.json", expanded=False):
        if _summary_available(pc_result):
            st.json(pc_result)
        else:
            st.info("데이터 없음")

    st.markdown('</div>', unsafe_allow_html=True)


# ------------------------------------------------------------------
# 메인 엔트리
# ------------------------------------------------------------------
def render_report():
    st.title("🔬 정찰 리포트")
    st.caption("PowerView, PingCastle, BloodHound 의 최신 결과를 하나의 리포트로 통합합니다.")

    # 인쇄용 CSS
    _inject_print_css()

    # 데이터 수집
    pv_summary = _safe_get_summary("powerview")
    pv_result = _safe_get_result("powerview")
    pc_summary = _safe_get_summary("pingcastle")
    pc_result = _safe_get_result("pingcastle")
    bh_collections = _list_bloodhound_collections()

    defaults = _extract_report_defaults(
        pv_summary=pv_summary,
        pv_result=pv_result,
        pc_summary=pc_summary,
    )

    # text_input은 key가 있으면 session_state 값이 우선 적용되므로,
    # 최초 진입 시 최신 정찰 결과에서 추출한 기본값을 채워준다.
    if "report_domain" not in st.session_state:
        st.session_state["report_domain"] = defaults["domain"]

    if "report_target_ip" not in st.session_state:
        st.session_state["report_target_ip"] = defaults["target_ip"]

    if "report_requested_by" not in st.session_state:
        st.session_state["report_requested_by"] = defaults["requested_by"]

    # 상단 입력 / 액션
    with st.container(border=True):
        c1, c2, c3 = st.columns([3, 3, 2])
        with c1:
            domain = st.text_input(
                "도메인",
                value=st.session_state.get("report_domain", "lab.local"),
                key="report_domain",
            )
        with c2:
            target_ip = st.text_input(
                "대상 IP",
                value=st.session_state.get("report_target_ip", ""),
                key="report_target_ip",
            )
        with c3:
            requested_by = st.text_input(
                "실행자",
                value=st.session_state.get("report_requested_by", ""),
                key="report_requested_by",
            )

        c_refresh, c_print = st.columns([1, 1])
        with c_refresh:
            if st.button("최신 결과 다시 불러오기", key="report_refresh"):
                st.rerun()
        with c_print:
            st.caption("PDF 저장이 필요하면 브라우저 인쇄(Ctrl+P) → 'PDF로 저장' 을 사용하세요.")

    # 위험 평가 계산 (Executive Summary와 PowerView 종합 양쪽에서 사용)
    risk_rows, overall_severity = _compute_risks(pv_summary)

    # 표지
    _render_cover(domain, target_ip, requested_by)

    # 1. Executive Summary
    _render_executive_summary(
        pv_summary,
        pc_summary,
        bh_collections,
        risk_rows,
        overall_severity,
    )

    # 2. PowerView 종합 (위험 평가 + 메트릭 + 상세 + 추천 공격 시나리오)
    _render_powerview_combined(pv_summary, pv_result, risk_rows, overall_severity)

    # 3. PingCastle 종합 (점수 요약 + HTML 임베드 + 점검/정책개선/권고사항)
    _render_pingcastle_combined(pc_summary, pc_result)

    # 4. BloodHound 그래프
    _render_bloodhound_section(bh_collections)

    # 5. 부록 - 원본 데이터
    _render_appendix(pv_result, pc_result)
