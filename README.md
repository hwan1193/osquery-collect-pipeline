# osquery-collect-pipeline
Windows에서 osqueryi를 호출해 보안 관련 아티팩트를 수집/요약하는 파이프라인
  
- 쿼리 실행 → JSON 저장  
- 휴리스틱으로 의심 항목 추출 → 관련 바이너리/레지스트리 하이브 등 **아티팩트 보존**  
- 최종 `report.json` + `suspicious_index.jsonl` + `artifacts_index.jsonl` 생성

> 차단/치료는 하지 않습니다. **포렌식/초기 triage 자동화** 목적입니다.

## ✨ 주요 기능
- 서비스/작업 스케줄/Temp 실행/외부 소켓/레지스트리 하이브 변경/서명 미검증 실행 파일 수집
- 의심 항목에 연결된 바이너리 자동 보존(해시 포함)
- 결과를 JSON/NDJSON으로 구조화 → 이후 SIEM/ELK/Teams 연동 용이

## 📦 요구 사항
- Windows(관리자 권한)
- osqueryi.exe (기본 경로: `C:\Program Files\osquery\osqueryi.exe`)

## 📁 구조
artifacts\	내용 요약 : 수집된 실제 파일(예: 비정상 서비스 exe, 스타트업 스크립트 등)	주요 용도 : 증거 파일 저장소

suspicious\suspicious_index.jsonl	내용 요약 : 의심 항목 목록 및 해시 정보					주요 용도 : 후속 분석용 로그

external_sokets.json	내용 요약 : 외부 네트워크 연결 목록(IP, Port, STATE)		주요 용도 : 외부 c2 서버 통신, 비정상 연결 탐지

hive_times.json		내용 요약 : SAM, SYSTEM, SECURITY 레지스트리 하이브의 수정시간	주요 용도 : 최근 계정·정책 변경 감시

host_info.json		내용 요약 : 호스트 OS 이름, 버전, 빌드 정보			주요 용도 : 시스템 기본 정보

listening_ports.json	내용 요약 : 현재 열려 있는 포트와 프로세스 PID, 프로토콜		주요 용도 : 불필요 서비스/백도어 포트 확인

processes_tmp.json	내용 요약 : C:Windows\temp 등에서 실행 중인 프로세스		주요 용도 : 임시 폴더 기반 악성 실행 탐지

report.json	내용 요약 : 전체 쿼리 결과와 의심 항목이 통합된 메인 요약			주요 용도 : 전체 분석 결과 (SIEM, 알람 연동 시 사용)

scheduled_tasks.json	내용 요약 : 예약 작업 (Task scheduler) 목록			주요 용도 : 자동 실행되는 악성 작업 탐지

services_custom.json	내용 요약 : 비표준 경로 서비스 (C:\Windows\System32 외 경로)	주요 용도 : 비정상 서비스 등록 탐지

startup_items.json	내용 요약 : 시작 프로그램 (Run, Startup 폴더 등)			주요 용도 : 자동 실행되는 앱 목록

unsigned_running.json	내용 요약 : 서명되지 않은 실행 중 프로세스 목록			주요 용도 : 악성코드 가능성 높은 프로세스 식별

users.json		내용 요약 : 시스템 사용자 계정 목록				주요 용도 : 불필요/의심 계정 존재 여부 확인

windows_packages.json	내용 요약 : 설치된 프로그램 중 주요 패키지 (OpenSSL, Apache 등)	주요 용도 : 취약 버전 여부 확인용

<img width="1828" height="612" alt="image" src="https://github.com/user-attachments/assets/fc4b94d9-6afd-4f74-9546-9a84ac828603" />


## 🚀 빠른 시작
```powershell
# 관리자 PowerShell
git clone https://github.com/<you>/osquery-collect-pipeline.git
cd osquery-collect-pipeline

# (선택) osquery 경로/출력 기본 경로를 환경변수로 바꿀 수 있습니다.
$env:OSQUERYI_BIN = 'C:\Program Files\osquery\osqueryi.exe'
$env:OUT_BASE     = 'C:\sec\osquery_auto'

# 실행
powershell -ExecutionPolicy Bypass -File .\scripts\osquery_collect_pipeline.ps1

C:\sec\osquery_auto\20250115_141522\
  artifacts\                # 수집된 실행 파일 등
  suspicious\               # 인덱스(NDJSON)
    artifacts_index.jsonl
    suspicious_index.jsonl
  *.json                    # 각 쿼리의 원본 결과(JSON)
  report.json               # 전체 요약

보안/운영 유의

민감 경로/파일을 저장하므로 격리된 출력 경로 사용 권장

공용 저장소에 실제 결과를 올리지 마세요 (샘플만, 마스킹 필수)

도구는 탐지/수집용이며 차단/격리는 하지 않습니다.
