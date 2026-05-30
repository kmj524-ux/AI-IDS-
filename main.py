import anthropic
import json
import re
import time
import random
from collections import defaultdict
from IPython.display import display, Markdown, clear_output

client = anthropic.Anthropic(
    api_key="sk-ant-여기에_API_KEY"
)

sample_logs = """
2024-01-15 09:23:11 192.168.1.105->10.0.0.1 PORT_SCAN ports:22,23,25,80,443
2024-01-15 09:24:55 192.168.1.105->10.0.0.1 SSH_FAIL username:admin attempts:47
2024-01-15 09:31:02 203.0.113.42->10.0.0.5 HTTP GET /admin/../../etc/passwd
2024-01-15 09:45:18 10.10.10.200->broadcast FLOOD packets:5000/sec
2024-01-15 10:02:33 172.16.0.9->10.0.0.8 NORMAL GET /index.html
"""

def parse_network_logs(log_text):
    parsed_logs = []

    pattern = re.compile(
        r"(?P<date>\d{4}-\d{2}-\d{2}) "
        r"(?P<time>\d{2}:\d{2}:\d{2}) "
        r"(?P<source_ip>[0-9\.]+)->(?P<destination_ip>[0-9\.a-zA-Z]+) "
        r"(?P<event>.+)"
    )

    for line in log_text.strip().split("\n"):
        match = pattern.match(line.strip())
        if match:
            parsed_logs.append(match.groupdict())

    return parsed_logs

def classify_attack(event):
    event = event.upper()

    if "PORT_SCAN" in event:
        return "포트 스캔"
    if "SSH_FAIL" in event or "LOGIN_FAIL" in event:
        return "브루트포스"
    if "FLOOD" in event or "PACKETS" in event:
        return "DDoS"
    if "../" in event or "SQL_INJECTION" in event or "OR 1=1" in event:
        return "웹 공격"

    return "정상 트래픽"

def calculate_risk_score(event, attack_type):
    event = event.upper()

    if attack_type == "DDoS":
        return 10

    if attack_type == "웹 공격":
        return 9

    if attack_type == "포트 스캔":
        return 8

    if attack_type == "브루트포스":
        attempts = re.search(r"attempts:(\d+)", event)

        if attempts:
            count = int(attempts.group(1))

            if count >= 50:
                return 9
            if count >= 20:
                return 7

            return 5

        return 7

    return 1

def get_risk_level(score):
    if score >= 9:
        return "매우 위험"
    if score >= 7:
        return "위험"
    if score >= 4:
        return "주의"

    return "안전"

def suggest_action(attack_type):
    actions = {
        "포트 스캔": "불필요한 포트를 닫고, 해당 IP를 감시 목록에 추가한다.",
        "브루트포스": "로그인 시도 횟수를 제한하고, 계정 잠금 정책을 적용한다.",
        "DDoS": "트래픽을 제한하고, 방화벽에서 위험 IP를 차단한다.",
        "웹 공격": "웹 방화벽을 적용하고, 의심스러운 URL 요청을 차단한다.",
        "정상 트래픽": "정상적인 접속이므로 추가 조치는 필요하지 않다."
    }

    return actions.get(attack_type, "추가 분석이 필요하다.")

def run_ids_analysis(log_text):
    parsed_logs = parse_network_logs(log_text)

    results = []
    ip_groups = defaultdict(list)

    for log in parsed_logs:
        attack_type = classify_attack(log["event"])
        score = calculate_risk_score(log["event"], attack_type)
        risk_level = get_risk_level(score)
        action = suggest_action(attack_type)

        result = {
            "time": f"{log['date']} {log['time']}",
            "source_ip": log["source_ip"],
            "destination_ip": log["destination_ip"],
            "event": log["event"],
            "attack_type": attack_type,
            "score": score,
            "risk_level": risk_level,
            "action": action
        }

        results.append(result)
        ip_groups[log["source_ip"]].append(result)

    return results, ip_groups

def ai_summary_analysis(log_text):
    prompt = f"""
아래 네트워크 로그를 일반인도 이해할 수 있게 분석해줘.

반드시 JSON 형식으로만 출력해.

형식:
{{
  "one_line_summary": "한 줄 요약",
  "main_problem": "가장 큰 문제",
  "dangerous_ip": "가장 위험한 IP",
  "easy_explanation": "쉬운 설명",
  "recommended_response": "추천 대응 방법"
}}

로그:
{log_text}
"""

    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1000,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    raw = response.content[0].text.strip()

    if raw.startswith("```"):
        raw = raw.split("```")[1]

        if raw.startswith("json"):
            raw = raw[4:]

        raw = raw.strip()

    return json.loads(raw)

def display_project_intro():
    display(Markdown("""
# AI 네트워크 침입 탐지 시스템

이 프로그램은 네트워크 로그를 분석해서 수상한 접속이나 공격 시도를 찾아내는 IDS입니다.

## 핵심 기능

### 1. 네트워크 로그 분석
접속 기록과 트래픽 데이터를 분석합니다.

### 2. 침입 유형 분류
포트 스캔, 브루트포스, DDoS, 웹 공격을 구분합니다.

### 3. 위험도 점수 산출
공격 가능성을 0점부터 10점까지 계산합니다.

### 4. 대응 방법 제안
위험 IP를 표시하고 차단, 모니터링 같은 대응 방법을 알려줍니다.

---
"""))

def display_analysis_results(results, ip_groups):
    threat_count = len([r for r in results if r["attack_type"] != "정상 트래픽"])
    normal_count = len([r for r in results if r["attack_type"] == "정상 트래픽"])

    display(Markdown(f"""
# 분석 결과 요약

- 전체 로그 수: **{len(results)}개**
- 탐지된 위협: **{threat_count}개**
- 정상 트래픽: **{normal_count}개**
"""))

    display(Markdown("---"))
    display(Markdown("# 상세 분석"))

    for idx, r in enumerate(results, start=1):
        if r["attack_type"] == "정상 트래픽":
            icon = "✅"
        elif r["score"] >= 9:
            icon = "🔥"
        elif r["score"] >= 7:
            icon = "⚠️"
        else:
            icon = "🔍"

        display(Markdown(f"""
## {icon} 로그 {idx}

| 항목 | 내용 |
|---|---|
| 시간 | `{r['time']}` |
| 출발지 IP | `{r['source_ip']}` |
| 목적지 IP | `{r['destination_ip']}` |
| 로그 내용 | `{r['event']}` |
| 분류 결과 | **{r['attack_type']}** |
| 위험도 점수 | **{r['score']} / 10** |
| 위험 등급 | **{r['risk_level']}** |
| 대응 방법 | {r['action']} |
"""))

    display(Markdown("---"))
    display(Markdown("# IP별 위험도"))

    for ip, logs in ip_groups.items():
        avg_score = round(sum(log["score"] for log in logs) / len(logs), 1)
        max_score = max(log["score"] for log in logs)

        if max_score >= 9:
            result = "차단 권장"
            icon = "🚫"
        elif max_score >= 7:
            result = "집중 모니터링"
            icon = "⚠️"
        elif max_score >= 4:
            result = "주의 관찰"
            icon = "🔍"
        else:
            result = "정상"
            icon = "✅"

        attack_types = list(set(log["attack_type"] for log in logs))

        display(Markdown(f"""
## {icon} `{ip}`

- 평균 위험도: **{avg_score} / 10**
- 최고 위험도: **{max_score} / 10**
- 판단 결과: **{result}**
- 발견된 유형: **{", ".join(attack_types)}**
- 관련 로그 수: **{len(logs)}개**
"""))

def display_ai_summary(ai_result):
    display(Markdown(f"""
---

# AI 종합 판단

## 한 줄 요약
{ai_result["one_line_summary"]}

## 가장 큰 문제
{ai_result["main_problem"]}

## 가장 위험한 IP
`{ai_result["dangerous_ip"]}`

## 쉬운 설명
{ai_result["easy_explanation"]}

## 추천 대응
{ai_result["recommended_response"]}
"""))

def run_once(log_text):
    clear_output(wait=True)

    display_project_intro()

    results, ip_groups = run_ids_analysis(log_text)
    display_analysis_results(results, ip_groups)

    try:
        ai_result = ai_summary_analysis(log_text)
        display_ai_summary(ai_result)

    except Exception as e:
        display(Markdown(f"""
# AI 요약 실패

AI API 호출 중 문제가 발생했습니다.

오류 내용:
`{e}`

기본 IDS 분석 결과는 정상적으로 출력되었습니다.
"""))

def generate_realtime_log():
    source_ips = [
        "192.168.1.105",
        "203.0.113.42",
        "10.10.10.200",
        "172.16.0.9",
        "45.77.12.88"
    ]

    destination_ips = [
        "10.0.0.1",
        "10.0.0.5",
        "10.0.0.8",
        "broadcast"
    ]

    events = [
        "PORT_SCAN ports:22,23,25,80,443",
        "SSH_FAIL username:admin attempts:47",
        "HTTP GET /admin/../../etc/passwd",
        "FLOOD packets:5000/sec",
        "NORMAL GET /index.html",
        "NORMAL GET /notice.html",
        "SQL_INJECTION ' OR 1=1 --"
    ]

    now = time.strftime("%Y-%m-%d %H:%M:%S")

    return (
        f"{now} "
        f"{random.choice(source_ips)}->{random.choice(destination_ips)} "
        f"{random.choice(events)}"
    )

def realtime_monitoring(seconds=10):
    collected_logs = ""

    for i in range(seconds):
        new_log = generate_realtime_log()
        collected_logs += new_log + "\n"

        clear_output(wait=True)

        display(Markdown(f"""
# 실시간 IDS 모니터링

현재 **{i + 1}초째** 네트워크 로그를 감시하고 있습니다.

## 방금 수집된 로그
`{new_log}`
"""))

        results, ip_groups = run_ids_analysis(collected_logs)
        display_analysis_results(results, ip_groups)

        time.sleep(1)

run_once(sample_logs)

# 실시간 모니터링 실행할 때만 아래 코드 사용
# realtime_monitoring(seconds=10)
