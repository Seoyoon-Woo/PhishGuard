

from urllib.parse import urlparse
import whois
from datetime import datetime

def analyze_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    risk_score = 0
    reasons = []
    details = []

    # 점수를 기록하는 함수
    def add_risk(label, points, reason):
        nonlocal risk_score
        risk_score += points
        reasons.append(reason)
        details.append({
            "항목": label,
            "점수": points,
            "설명": reason
        })

    # 도메인 생성일 확인
    try:
        if hostname:
            domain_info = whois.whois(hostname)
            creation_date = domain_info.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                days = (
                    datetime.now() -
                    creation_date.replace(tzinfo=None)
                ).days

                if days < 180:
                    add_risk(
                        "도메인 생성일",
                        20,
                        "생성된 지 180일 미만인 도메인"
                    )

    except Exception:
        pass

    # HTTPS 검사
    if parsed.scheme != "https":
        add_risk(
            "HTTPS 검사",
            20,
            "HTTPS를 사용하지 않는 URL"
        )

    # IP 주소 검사
    if hostname.replace(".", "").isdigit():
        add_risk(
            "IP 주소 검사",
            30,
            "IP 주소를 직접 사용하는 URL"
        )

    # URL 길이 검사
    if len(url) > 75:
        add_risk(
            "URL 길이 검사",
            10,
            "URL이 비정상적으로 긴 편"
        )

    # @ 기호 검사
    if "@" in url:
        add_risk(
            "@ 기호 검사",
            20,
            "@ 기호가 포함된 URL"
        )

    # 도메인 하이픈 검사
    if hostname.count("-") >= 2:
        add_risk(
            "하이픈 검사",
            10,
            "도메인에 하이픈이 여러 개 포함됨"
        )
    
    
    # URL 경로 검사
    path = parsed.path

    if len(path.split("/")) >= 5:
        add_risk(
            "URL 경로 검사",
            10,
            "URL 경로가 여러 단계로 구성됨"
        )


    

    # 의심 키워드 검사
    suspicious_words = [
        "login", "verify", "account",
        "password", "secure", "update"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if len(found_words) >= 3:
        add_risk(
            "의심 키워드 검사",
            15,
            f"의심 키워드가 여러 개 발견됨: {', '.join(found_words)}"
        )
    elif len(found_words) == 2:
        add_risk(
            "의심 키워드 검사",
            10,
            f"의심 키워드 발견: {', '.join(found_words)}"
        )


    # 최대 점수 100점
    risk_score = min(risk_score, 100)

    if risk_score >= 40:
        verdict = "위험"
    elif risk_score >= 20:
        verdict = "주의"
    else:
        verdict = "낮은 위험"

    if not reasons:
        reasons.append("특별한 위험 요소가 발견되지 않았습니다.")

    return {
        "url": url,
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons,
        "details": details
    }


if __name__ == "__main__":
    url = input("분석할 URL을 입력하세요: ")
    result = analyze_url(url)
    print(result)
