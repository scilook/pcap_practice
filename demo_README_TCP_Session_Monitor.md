# 일러두기
- demo* 는 실행 및 기능 확인을 위해 생성형 에이전트를 통해 만든 내용임.
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
- **평균 RTT**: 연결 RTT와 모든 데이터 RTT의 평균값 계산
- **스마트 RTT 표시**: 측정 가능한 RTT에 따라 적응적 출력

### 3. 처리율 (Throughput) 계산  
- **실시간 처리율**: 실제 데이터 전송 기간 동안의 처리율 계산
- **정확한 시간 측정**: 첫 번째~마지막 데이터 패킷 시간 기반
- **예외 상황 처리**: 데이터 없음, 순간 전송 등 특수 케이스 대응

### 4. 재전송 탐지
- **방향별 SEQ 추적**: 클라이언트(C)와 서버(S) 방향 구분하여 추적
- **정확한 재전송 감지**: 같은 방향의 동일 SEQ 번호만 재전송으로 판단
- **실시간 재전송 알림**: 재전송 발생 시 즉시 출력

### 5. 세션 상태 관리
- **핸드셰이크 추적**: SYN, SYN+ACK, ACK 순서 추적
- **연결 수립 감지**: 3-way handshake 완료 확인
- **세션 종료 감지**: FIN 또는 RST 플래그 감지

## 데이터 구조

### t_tcp_session 구조체
```c
typedef struct s_tcp_session {
    // 세션 식별 정보  
    char src_ip[16], dst_ip[16];
    unsigned short src_port, dst_port;
    
    // RTT 관련
    double conn_rtt;              // 연결 수립 RTT (3-way handshake)
    double total_rtt;             // 모든 RTT 합계 (conn_rtt + data_rtt들)
    int rtt_count;                // RTT 측정 횟수
    t_list *pending_seqs;         // 대기 중인 SEQ 번호들 (RTT 계산용)
    
    // 핸드셰이크 추적
    int syn_seen;
    struct timeval syn_time;
    int syn_ack_seen;
    int established;
    
    // 세션 통계
    long long total_bytes;        // 총 전송 바이트
    struct timeval first_data_time; // 첫 번째 데이터 패킷 시간
    struct timeval last_data_time;  // 마지막 데이터 패킷 시간
    int has_data;                 // 데이터 패킷이 있는지 여부
    
    // 재전송 탐지용 변수
    int retrans_count;            // 재전송 카운트
    t_list *seen_seqs;            // 이미 확인된 SEQ 번호들
    
    // 세션 상태
    int total_packets;            // 총 패킷 수
    int session_closed;           // 세션 종료 상태
} t_tcp_session;
```

## 사용법

### 컴파일
```bash
# 기본 빌드
make

# 또는 직접 컴파일
gcc -o demo_capture demo_capture.c utils.c -lpcap

# 디버그 빌드
make debug
```

### 실행 (관리자 권한 필요)
```bash
# 기본 실행
sudo ./demo_capture

# 또는 Makefile 사용
make run
```

### 중지
- `Ctrl+C`를 눌러 프로그램을 중지하면 모든 세션의 요약 정보가 출력됩니다.

### Makefile 타겟
```bash
make help          # 사용 가능한 모든 타겟 확인
make all           # 기본 빌드 (기본값)
make clean         # 오브젝트 파일 정리  
make fclean        # 실행 파일까지 모두 정리
make re            # 완전 재빌드 (fclean + all)
make run           # 빌드 후 sudo로 실행
make debug         # 디버그 심볼 포함해서 빌드
make install-deps  # Ubuntu/Debian용 의존성 설치
```

### 출력 해석
- **Connection RTT**: 3-way handshake 시간
- **Avg RTT**: 연결 RTT + 모든 데이터 RTT의 평균
- **"(connection only)"**: 데이터 RTT 측정 안됨, 연결 RTT만 표시
- **"N/A (no RTT measurements)"**: 어떤 RTT도 측정되지 않음
- **Throughput**: 실제 데이터 전송 기간 동안의 전송률 (bytes/sec)

## 출력 예시

### 실시간 모니터링
```
Using device: eth0
Starting TCP session monitoring...
Press Ctrl+C to stop and view summary

[NEW SESSION] 10.0.4.19:52341 <-> 93.184.216.34:80
[HANDSHAKE] SYN detected for session 10.0.4.19:52341 <-> 93.184.216.34:80
[HANDSHAKE] SYN+ACK detected, Connection RTT: 15.234 ms
[HANDSHAKE] Connection established for session 10.0.4.19:52341 <-> 93.184.216.34:80
[RETRANSMISSION] SEQ 1234567890 (C) detected in session 10.0.4.19:52341 <-> 93.184.216.34:80
[SESSION_END] Session 10.0.4.19:52341 <-> 93.184.216.34:80 closed
[SESSION_END] Throughput: 1566511.09 bytes/sec
```

### 최종 요약 보고서
```
======= TCP SESSION ANALYSIS SUMMARY =======

===== Session Summary =====
Session: 10.0.4.19:52341 <-> 93.184.216.34:80
Total Packets: 147
Data Transferred: 1.25 MB
Connection RTT: 15.2 ms
Avg RTT: 14.8 ms
Retransmissions: 3
===========================

===== Session Summary =====
Session: 10.0.4.19:52342 <-> 140.82.114.21:443
Total Packets: 25
Data Transferred: 4.35 KB
Avg RTT: N/A (no RTT measurements)
Retransmissions: 0
===========================

===== Session Summary =====
Session: 10.0.4.19:52343 <-> 52.239.197.69:443
Total Packets: 20
Data Transferred: 8.68 KB
Connection RTT: 231.4 ms
Avg RTT: 231.4 ms (connection only)
Retransmissions: 0
===========================

Total Sessions Monitored: 3
============================================
```

## 기술적 특징

### 1. 메모리 효율성
- 제네릭 연결 리스트(t_list) 기반 동적 메모리 관리
- 세션 종료 시 자동 메모리 해제 (lst_clear 사용)
- 확장 가능한 데이터 구조

### 2. 정확한 측정
- 패킷 타임스탬프 기반 마이크로초 단위 정밀 측정
- 양방향 트래픽 통합 분석 (4-튜플 정규화)
- 방향별 재전송 탐지로 오탐 방지
- 표준 네트워크 헤더 구조체 사용 (struct ip, struct tcphdr)

### 3. 실시간 처리
- 패킷 도착 즉시 분석 및 업데이트
- 신호 처리를 통한 안전한 종료 (SIGINT)
- 최소한의 오버헤드로 고성능 처리

### 4. 강건한 RTT 측정
- 다양한 RTT 측정 시나리오 지원:
  - 정상적인 평균 RTT 계산
  - 연결 RTT만 측정된 경우 "(connection only)" 표시
  - RTT 측정 불가능한 경우 "N/A" 표시
- SEQ-ACK 매칭 기반 정확한 데이터 RTT 계산

## 확장 가능성

1. **고급 통계**: 지터(Jitter), 패킷 손실률 등 추가 네트워크 메트릭
2. **데이터베이스 연동**: 장기간 세션 데이터 저장 및 분석
3. **웹 인터페이스**: 실시간 모니터링 대시보드
4. **알람 시스템**: RTT 임계값, 재전송률 등 기준 초과 시 알림
5. **필터링 확장**: IP/포트 범위, 프로토콜별 세밀한 필터링
6. **성능 최적화**: 해시 테이블 기반 세션 검색, 메모리 풀 등

## 주요 개선사항 (기존 대비)

1. **정확한 재전송 탐지**: 방향별 SEQ 추적으로 오탐 제거
2. **표준 헤더 사용**: struct ip, struct tcphdr로 호환성 향상  
3. **강화된 RTT 측정**: 다양한 시나리오에 대한 적응적 RTT 표시
4. **실용적 처리율 계산**: 실제 데이터 전송 시간 기반 정확한 측정
5. **메모리 안전성**: 표준 연결 리스트와 안전한 메모리 관리
6. **코드 간소화**: 불필요한 구조체 및 변수 제거로 효율성 향상

## 제한사항

1. **권한 요구**: 패킷 캡처를 위해 관리자 권한 필요
2. **네트워크 인터페이스**: 로컬 네트워크 인터페이스 트래픽만 캡처
3. **세션 중간 시작**: 실행 시점 이전에 시작된 세션은 불완전한 정보
4. **메모리 사용**: 장시간 실행 시 많은 세션으로 인한 메모리 증가 가능
5. **암호화 트래픽**: HTTPS 등 암호화된 애플리케이션 데이터는 분석 불가

## 빌드 요구사항

- **운영체제**: Linux (Ubuntu, CentOS, RHEL 등)
- **컴파일러**: GCC 
- **라이브러리**: libpcap-dev (Debian/Ubuntu) 또는 libpcap-devel (RHEL/CentOS)
- **권한**: sudo 권한 (패킷 캡처용)

### 의존성 설치
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install libpcap-dev

# CentOS/RHEL/Fedora  
sudo yum install libpcap-devel
# 또는
sudo dnf install libpcap-devel
```

## 개선된 점

기존 단일 세션 추적 방식에서 다음과 같이 개선되었습니다:

1. **다중 세션 지원**: 동시에 여러 TCP 세션 추적 및 관리
2. **정확한 세션 식별**: 4-튜플 기반 고유 식별 및 양방향 정규화
3. **향상된 재전송 탐지**: 방향별 SEQ 추적으로 오탐지 방지
4. **적응적 RTT 측정**: 다양한 측정 상황에 대한 유연한 처리
5. **실용적 처리율**: 실제 데이터 전송 시간 기반 정확한 계산
6. **표준 호환성**: 표준 네트워크 헤더 구조체 사용으로 호환성 향상
7. **메모리 최적화**: 불필요한 데이터 구조 제거 및 효율적 관리
8. **안전한 종료**: 신호 처리를 통한 정상적인 프로그램 종료
