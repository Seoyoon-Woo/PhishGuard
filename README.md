# 🛡️ PhishGuard

**규칙 기반 피싱 URL 위험도 분석 시스템**

## 1. 프로젝트 소개
PhishGuard는 URL에 포함된 다양한 위험 요소를 분석하여 피싱 가능성을 점수와 판정으로 제공하는 웹 기반 보안 프로젝트입니다.

## 2. 주요 기능
- URL 위험도 점수 분석
- HTTPS 사용 여부 검사
- IP 주소 직접 사용 여부 검사
- 의심 키워드 탐지
- URL 길이 및 경로 검사
- 도메인 생성일 확인
- 위험 요소별 상세 분석
- URL 기본 정보 표시
- 분석 이력 및 통계 대시보드
- CSV 분석 보고서 다운로드
- 과거 분석 결과 재확인

## 3. 개발 환경
- Language: Python
- Framework: Streamlit
- Libraries: python-whois, pandas
- Editor: Visual Studio Code

## 4. 실행 방법

프로젝트 폴더에서 터미널을 열고 다음 명령어를 실행합니다.

```bash
.\venv\Scripts\python.exe -m streamlit run web_app.py
```

## 5. 분석 방식
URL의 구조와 보안 관련 특징을 규칙 기반으로 분석하여 위험 점수를 산출합니다.

※ 본 프로젝트는 학습 및 연구 목적의 프로토타입이며, URL의 안전성을 완벽하게 보장하지 않습니다.

## 6. 프로젝트 목적
피싱 URL 탐지 원리를 이해하고 Python을 활용한 보안 분석 시스템을 직접 구현하는 것을 목표로 합니다.