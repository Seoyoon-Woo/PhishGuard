

import streamlit as st
from app import analyze_url
from urllib.parse import urlparse

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)

# 분석 이력 저장
if "history" not in st.session_state:
    st.session_state.history = []

# 다크 테마 디자인
st.markdown("""
<style>
.stApp {
    background-color: #101827;
    color: #F8FAFC;
}
.block-container {
    padding-top: 2rem;
    max-width: 1100px;
}
h1, h2, h3, p, label {
    color: #F8FAFC;
}
div[data-testid="stMetric"] {
    background: #1E293B;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #334155;
}
.stButton > button {
    background-color: #0284C7;
    color: white;
    border-radius: 8px;
    border: none;
    height: 45px;
    font-weight: bold;
}
.stButton > button:hover {
    background-color: #0369A1;
    color: white;
}
</style>
""", unsafe_allow_html=True)

# 상단 제목
st.title("🛡️ PhishGuard")
st.caption("CYBER SECURITY · PHISHING URL ANALYSIS SYSTEM")

st.divider()

# URL 입력
st.subheader("🔍 URL 보안 분석")

url = st.text_input(
    "분석할 URL을 입력하세요",
    placeholder="https://example.com"
)

# 분석 버튼
if st.button("🔍 URL 분석 시작", use_container_width=True):

    if not url:
        st.warning("URL을 입력해 주세요.")
        
    elif not url.startswith(("http://", "https://")):
        st.warning("http:// 또는 https://를 포함해 입력해 주세요.")

    elif not urlparse(url).hostname:
        st.warning("올바른 도메인 주소를 입력해 주세요.")


    else:
        with st.spinner("URL을 분석하고 있습니다..."):
            result = analyze_url(url)

        score = result["risk_score"]
        verdict = result["verdict"]

        # 분석 이력 저장
        
        st.session_state.history.append({
            "URL": url,
            "위험 점수": score,
            "판정": verdict,
            "탐지 항목": ", ".join(
                detail["항목"] for detail in result["details"]
            ),
            "상세 설명": ", ".join(result["reasons"])
        })


        # 분석 결과
        st.divider()
        st.subheader("📊 분석 결과")
        # URL 기본 정보
        st.subheader("🌐 URL 기본 정보")

        parsed_url = urlparse(url)

        info1, info2, info3 = st.columns(3)

        info1.metric("도메인", parsed_url.hostname or "-")
        info2.metric("프로토콜", parsed_url.scheme.upper())
        info3.metric("경로", parsed_url.path or "/")
        col1, col2 = st.columns(2)

        with col1:
            st.metric("위험 점수", f"{score} / 100")

        with col2:
            st.metric("보안 판정", verdict)

        st.progress(score / 100)

        # 위험도에 따른 안내 메시지
        if score >= 40:
            st.error("🚨 높은 위험도: 의심스러운 요소가 다수 발견되었습니다.")
        elif score >= 20:
            st.warning("⚠️ 중간 위험도: 추가적인 확인이 필요합니다.")
        else:
            st.success("✅ 낮은 위험도: 탐지된 위험 요소가 적습니다.")
        # 탐지 항목이 있을 때 추가 안내
        if result["details"] and score < 20:
            st.info(
                "ℹ️ 낮은 위험으로 판정되었지만, "
                "일부 의심 요소가 발견되었습니다. "
                "접속 전 추가 확인이 필요합니다."
            )
        
        # 위험 요소별 상세 분석
        st.subheader("🧾 위험 요소별 상세 분석")

        if result["details"]:
            for detail in result["details"]:
                col1, col2 = st.columns([3, 1])

                with col1:
                    st.write(f"**{detail['항목']}**")
                    st.caption(detail["설명"])

                with col2:
                    st.metric("위험 점수", f"+{detail['점수']}점")

                st.divider()

        else:
            st.success("특별한 위험 요소가 발견되지 않았습니다.")

        st.caption(
            "※ 이 결과는 규칙 기반 분석이며 "
            "URL의 안전성을 완벽하게 보장하지 않습니다."
        )

# 분석 통계 대시보드
st.divider()
st.subheader("📈 분석 통계")

total = len(st.session_state.history)

danger = sum(
    1 for item in st.session_state.history
    if item["판정"] == "위험"
)

caution = sum(
    1 for item in st.session_state.history
    if item["판정"] == "주의"
)

safe = sum(
    1 for item in st.session_state.history
    if item["판정"] == "낮은 위험"
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("총 분석 횟수", total)
col2.metric("위험", danger)
col3.metric("주의", caution)
col4.metric("낮은 위험", safe)

# 위험도별 비율 그래프
st.subheader("📊 위험도별 분석 비율")

chart_data = {
    "판정": ["위험", "주의", "낮은 위험"],
    "분석 횟수": [danger, caution, safe]
}

if total > 0:
    import pandas as pd

    chart_df = pd.DataFrame(chart_data)

    st.bar_chart(
        chart_df.set_index("판정")
    )
else:
    st.info("분석 기록이 쌓이면 그래프가 표시됩니다.")

# 분석 결과 다운로드
st.divider()
st.subheader("📥 분석 결과 다운로드")

if st.session_state.history:
    import pandas as pd

    report_df = pd.DataFrame(st.session_state.history)

    csv_data = report_df.to_csv(
        index=False,
        encoding="utf-8-sig"
    )

    st.download_button(
        label="📄 분석 결과 CSV 다운로드",
        data=csv_data,
        file_name="PhishGuard_Report.csv",
        mime="text/csv",
        use_container_width=True
    )
else:
    st.info("다운로드할 분석 기록이 없습니다.")

# 분석 이력
st.divider()
st.subheader("📚 URL 분석 이력")

if st.session_state.history:
    st.dataframe(
        st.session_state.history,
        use_container_width=True,
        hide_index=True
    )
    # 과거 분석 결과 선택
    st.subheader("🔎 과거 분석 결과 다시 보기")

    selected_index = st.selectbox(
        "확인할 분석 기록을 선택하세요.",
        range(len(st.session_state.history)),
        format_func=lambda i: st.session_state.history[i]["URL"]
    )

    selected_result = st.session_state.history[selected_index]

    st.write("**선택한 URL:**", selected_result["URL"])
    st.write("**위험 점수:**", selected_result["위험 점수"])
    st.write("**보안 판정:**", selected_result["판정"])
    st.write("**탐지 항목:**", selected_result.get("탐지 항목", "-"))
    st.write("**상세 설명:**", selected_result.get("상세 설명", "-"))
    if st.button("🗑️ 분석 이력 초기화"):
        st.session_state.history = []
        st.rerun()

else:
    st.info("아직 분석 이력이 없습니다.")

st.divider()
st.caption("PhishGuard | Cyber Security Project")
