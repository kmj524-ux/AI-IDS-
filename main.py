import re
import time
import random
import os
from collections import defaultdict
from datetime import datetime

LOG_FILE = "network.log"

ip_history = defaultdict(list)


def parse_log_line(line):
    pattern = re.compile(
        r"(?P<date>\d{4}-\d{2}-\d{2}) "
        r"(?P<time>\d{2}:\d{2}:\d{2}) "
        r"(?P<source_ip>[0-9\.]+)->(?P<destination_ip>[0-9\.a-zA-Z]+) "
        r"(?P<event>.+)"
    )

    match = pattern.match(line.strip())

    if not match:
        return None

    return match.groupdict()


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
        packets = re.search(r"packets:(\d+)", event)

        if packets:
            count = int(packets.group(1))

            if count >= 10000:
                return 10

            if count >= 5000:
                return 9

        return 8

    if attack_type == "웹 공격":
        return 9

    if attack_type == "포트 스캔":
        ports = re.search(r"ports:([0-9,]+)", event)

        if ports:
            port_count = len(ports.group(1).split(","))

            if port_count >= 5:
                return 8

            return 6

        return 7

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


def suggest_action(attack_type, score):
    if attack_type == "포트 스캔":
        return "불필요한 포트를 닫고, 해당 IP를 감시 목록에 추가하는 것이 좋습니다."

    if attack_type == "브루트포스":
        return "로그인 시도 횟수를 제한하고, 계정 잠금 정책을 적용하는 것이 좋습니다."

    if attack_type == "DDoS":
        return "트래픽 제한을 적용하고, 방화벽에서 해당 IP 차단을 검토해야 합니다."

    if attack_type == "웹 공격":
        return "웹 방화벽을 적용하고, 의심스러운 URL 요청을 차단해야 합니다."

    return "정상 트래픽으로 보이며, 추가 조치는 필요하지 않습니다."


def analyze_log(log):
    attack_type = classify_attack(log["event"])
    score = calculate_risk_score(log["event"], attack_type)
    risk_level = get_risk_level(score)
    action = suggest_action(attack_type, score)

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

    ip_history[log["source_ip"]].append(result)

    return result


def get_ip_risk_summary(ip):
    logs = ip_history[ip]

    avg_score = round(sum(log["score"] for log in logs) / len(logs), 1)
    max_score = max(log["score"] for log in logs)
    attack_types = sorted(set(log["attack_type"] for log in logs))

    if max_score >= 9:
        decision = "차단 검토"
    elif max_score >= 7:
        decision = "집중 모니터링"
    elif max_score >= 4:
        decision = "주의 관찰"
    else:
        decision = "정상"

    return {
        "avg_score": avg_score,
        "max_score": max_score,
        "attack_types": attack_types,
        "count": len(logs),
        "decision": decision
    }


def print_result(result):
    ip_summary = get_ip_risk_summary(result["source_ip"])

    print("\n" + "=" * 80)
    print("실시간 IDS 탐지 결과")
    print("=" * 80)

    print(f"시간: {result['time']}")
    print(f"출발지 IP: {result['source_ip']}")
    print(f"목적지 IP: {result['destination_ip']}")
    print(f"로그 내용: {result['event']}")

    print("-" * 80)

    print(f"침입 유형: {result['attack_type']}")
    print(f"위험도 점수: {result['score']} / 10")
    print(f"위험 등급: {result['risk_level']}")
    print(f"대응 방법: {result['action']}")

    print("-" * 80)

    print("IP별 누적 위험도")
    print(f"IP 주소: {result['source_ip']}")
    print(f"평균 위험도: {ip_summary['avg_score']} / 10")
    print(f"최고 위험도: {ip_summary['max_score']} / 10")
    print(f"발견된 유형: {', '.join(ip_summary['attack_types'])}")
    print(f"관련 로그 수: {ip_summary['count']}개")
    print(f"판단 결과: {ip_summary['decision']}")

    print("-" * 80)

    if result["attack_type"] == "정상 트래픽":
        print("최종 판단: 정상적인 접속으로 보입니다.")
    else:
        print("최종 판단: 수상한 네트워크 활동이 감지되었습니다.")

    print("=" * 80)


def create_log_file_if_missing():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as file:
            file.write("")

        print(f"{LOG_FILE} 파일을 새로 만들었습니다.")


def monitor_log_file():
    create_log_file_if_missing()

    print("실시간 네트워크 침입 탐지 시스템을 시작합니다.")
    print(f"감시 파일: {LOG_FILE}")
    print("새 로그가 추가되면 자동으로 분석합니다.")
    print("종료하려면 Ctrl + C를 누르세요.")
    print("=" * 80)

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            file.seek(0, 2)

            while True:
                line = file.readline()

                if not line:
                    time.sleep(1)
                    continue

                parsed_log = parse_log_line(line)

                if parsed_log:
                    result = analyze_log(parsed_log)
                    print_result(result)

                else:
                    print("\n분석할 수 없는 로그 형식입니다.")
                    print(f"원본 로그: {line.strip()}")

    except KeyboardInterrupt:
        print("\nIDS 감시를 종료했습니다.")


def make_test_log():
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

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return (
        f"{now} "
        f"{random.choice(source_ips)}->{random.choice(destination_ips)} "
        f"{random.choice(events)}"
    )


def add_test_logs(count=5, delay=1):
    create_log_file_if_missing()

    for _ in range(count):
        log = make_test_log()

        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(log + "\n")

        print(f"테스트 로그 추가: {log}")
        time.sleep(delay)


print("실행 모드를 선택하세요.")
print("1: IDS 감시 시작")
print("2: 테스트 로그 추가")
print("3: 종료")

mode = input("번호 입력: ")

if mode == "1":
    monitor_log_file()

elif mode == "2":
    count = input("추가할 테스트 로그 개수 입력: ")

    if count.isdigit():
        add_test_logs(count=int(count), delay=1)
    else:
        add_test_logs(count=5, delay=1)

else:
    print("프로그램을 종료합니다.")
