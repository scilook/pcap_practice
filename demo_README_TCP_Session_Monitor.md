# 일러두기
- demo* 는 실행 및 기능 확인을 위해 생성형 에이전트를 통해 만든 내용임.
- 학습자의 작업물은 접두사로 demo가 붙지 않은 모든 파일임.
- 학습자의 작업물 중 일부는 생성형 에이전트의 도움을 받을 수 있음.

# TCP 세션 모니터링 프로그램

## 개요
이 프로그램은 제안된 TCP 세션 중심 설계를 구현하여 여러 TCP 세션을 개별적으로 추적하고 분석하는 도구입니다.

## 주요 기능

### 1. 다중 세션 추적
- **4-튜플 기반 세션 식별**: (출발지IP:포트, 목적지IP:포트)
- **양방향 통신 정규화**: 같은 연결의 양방향 패킷을 하나의 세션으로 통합
- **동적 세션 관리**: 새로운 세션 자동 생성 및 종료 감지

### 2. RTT (왕복 시간) 측정
- **연결 RTT**: 3-way handshake (SYN → SYN+ACK) 시간 측정
- **데이터 RTT**: 데이터 패킷과 ACK 패킷 간의 시간 측정
- **실시간 RTT 업데이트**: 최신 데이터 RTT 지속적 업데이트

### 3. 처리율 (Throughput) 계산
- **1초별 처리율**: 각 초마다 전송된 바이트 수 추적
- **평균 처리율**: 전체 세션 기간 동안의 평균 처리율
- **최대 처리율**: 가장 높은 1초간 처리율 (Peak Throughput)

### 4. 재전송 탐지
- **SEQ 번호 추적**: 이미 전송된 SEQ 번호들을 기록
- **재전송 카운트**: 중복 SEQ 번호 발견 시 재전송으로 간주
- **실시간 재전송 알림**: 재전송 발생 시 즉시 출력

### 5. 세션 상태 관리
- **핸드셰이크 추적**: SYN, SYN+ACK, ACK 순서 추적
- **연결 수립 감지**: 3-way handshake 완료 확인
- **세션 종료 감지**: FIN 또는 RST 플래그 감지

## 데이터 구조

### tcp_session_t 구조체
```c
typedef struct tcp_session {
    // 세션 식별 정보
    char src_ip[16], dst_ip[16];
    unsigned short src_port, dst_port;
    
    // RTT 관련
    double conn_rtt;              // 연결 RTT
    double latest_data_rtt;       // 최근 데이터 RTT
    seq_entry_t *pending_seqs;    // 대기 중인 SEQ 목록
    
    // 처리율 관련
    long long total_bytes;        // 총 전송 바이트
    throughput_entry_t *throughput_list; // 1초별 처리율
    
    // 재전송 관련
    int retrans_count;            // 재전송 횟수
    seq_entry_t *seen_seqs;       // 확인된 SEQ 목록
    
    // 세션 상태
    int total_packets;            // 총 패킷 수
    int session_closed;           // 종료 여부
    
    struct tcp_session *next;     // 연결 리스트
} tcp_session_t;
```

## 사용법

### 컴파일
```bash
gcc -o demo demo.c -lpcap
```

### 실행 (관리자 권한 필요)
```bash
sudo ./demo
```

### 중지
- `Ctrl+C`를 눌러 프로그램을 중지하면 모든 세션의 요약 정보가 출력됩니다.

## 출력 예시

### 실시간 모니터링
```
Using device: eth0
Starting TCP session monitoring...
Press Ctrl+C to stop and view summary

[NEW SESSION] 192.168.1.100:52341 <-> 93.184.216.34:80
[HANDSHAKE] SYN detected for session 192.168.1.100:52341 <-> 93.184.216.34:80
[HANDSHAKE] SYN+ACK detected, Connection RTT: 15.234 ms
[HANDSHAKE] Connection established for session 192.168.1.100:52341 <-> 93.184.216.34:80
```

### 최종 요약 보고서
```
======= TCP SESSION ANALYSIS SUMMARY =======

===== Session Summary =====
Session: 192.168.1.100:52341 <-> 93.184.216.34:80
Total Packets: 147
Data Transferred: 1.25 MB
Connection RTT: 15.2 ms
Latest Data RTT: 12.8 ms
Retransmissions: 3
Average Throughput: 256.7 Kbps
Peak Throughput: 512.3 Kbps
Status: Closed
=========================

Total Sessions Monitored: 1
============================================
```

## 기술적 특징

### 1. 메모리 효율성
- 동적 메모리 할당으로 필요한 만큼만 메모리 사용
- 세션 종료 시 자동 메모리 해제
- 연결 리스트 기반의 확장 가능한 구조

### 2. 정확한 측정
- 패킷 타임스탬프 기반 정밀한 시간 측정
- 양방향 트래픽 통합 분석
- TCP 프로토콜 상태 기반 정확한 세션 추적

### 3. 실시간 처리
- 패킷 도착 즉시 분석 및 업데이트
- 백그라운드 데이터 구조 관리
- 최소한의 오버헤드로 고성능 처리

## 확장 가능성

1. **데이터베이스 연동**: 세션 데이터를 데이터베이스에 저장
2. **웹 인터페이스**: 실시간 모니터링 대시보드
3. **알람 시스템**: 임계값 초과 시 알림
4. **통계 분석**: 장기간 트렌드 분석
5. **필터링**: 특정 IP/포트 범위만 모니터링

## 제한사항

1. **권한 요구**: 패킷 캡처를 위해 관리자 권한 필요
2. **네트워크 인터페이스**: 로컬 네트워크 트래픽만 캡처 가능
3. **메모리 사용**: 장시간 실행 시 많은 세션으로 인한 메모리 증가 가능

## 개선된 점

기존 단일 세션 추적 방식에서 다음과 같이 개선되었습니다:

1. **다중 세션 지원**: 동시에 여러 TCP 세션 추적
2. **정확한 세션 식별**: 4-튜플 기반 고유 식별
3. **양방향 통신 통합**: 같은 연결의 양방향 패킷을 하나로 처리
4. **상세한 성능 지표**: RTT, 처리율, 재전송 등 종합적 분석
5. **실시간 모니터링**: 세션 생성부터 종료까지 전 과정 추적
