# FOR-004 방어 노트 (Blue)

## 무슨 일이 있었나
공격자가 임원을 사칭(From 위조)해 송금을 유도하는 BEC/피싱을 보냈다(ATT&CK **T1566** Phishing).
From은 위조 가능하지만 **Received 체인의 최초 홉**(맨 아래)은 실제 발신 인프라(`198.51.100.77`)를 남긴다.

## 탐지/분석
- **Received 체인 역추적**: 위(수신측)→아래(발신측) 순으로 읽어 최초 홉의 IP/호스트를 확인.
- **Reply-To/Return-Path 불일치**: From과 다른 외부 도메인이면 사칭 의심.
- **인증 결과 확인**: `Authentication-Results` 헤더의 SPF/DKIM/DMARC fail.

## 완화
- **SPF/DKIM/DMARC** 강제(수신 정책 reject) — 도메인 스푸핑을 근본 차단.
- 외부 발신 배너 표시, 송금 등 고위험 요청은 대역외(전화) 재확인 절차.
