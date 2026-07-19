# RLS Guard 실행 루프

## 이번 공개 글

본문에는 링크를 넣지 않는다. 개선 과정과 한계를 먼저 공개하고, 무료 스캐너와 유료 키트 링크는 발행 직후 자기 댓글에 단다.

### 본문 초안

Supabase RLS 사용자 니즈를 다시 뜯어보니, 제가 만든 도구도 3가지가 비어 있었습니다.

1. 역할별 권한을 한눈에 설계하는 표
2. anon/member/owner/service_role 실제 테스트
3. Dashboard 변경이 migration에서 빠졌는지 확인하는 방법

그래서 오늘 RLS Guard Security Kit에
- 역할 × CRUD × 리소스 매트릭스
- pgTAP 16개와 CI
- 원격 schema drift 탐지
를 추가했습니다.

아직 로컬 Docker가 없어 pgTAP 실실행은 CI에서 최종 확인해야 합니다. 완성됐다고 포장하지 않고 그 결과도 공개하겠습니다.

이 제품과 글은 AI와 함께 만들고 있습니다.

### 자기 댓글 초안

무료 SQL 검사기: https://rls-guard-rose.vercel.app/?utm_source=threads&utm_medium=social&utm_campaign=needs_update

역할 테스트와 drift 템플릿이 포함된 실전 보안 킷: https://www.latpeed.com/products/8kJtX?utm_source=threads&utm_medium=social&utm_campaign=needs_update

정적 분석과 템플릿은 프로젝트별 보안 감사나 실제 접근 테스트를 대신하지 않습니다.

## 측정 규칙

- 발행 직후: URL과 발행 시각 기록
- 1시간 후: 조회, 좋아요, 답글, 리포스트, 공유, 판매 기록
- 4시간 후: 같은 항목 재측정
- 판매 0이고 질문도 0이면 다음 글은 판매 설명이 아니라 실제 SQL 전후 사례를 공개
- 질문이 생기면 30분 안에 답하고, 반복 질문은 랜딩 FAQ 또는 키트 문서에 반영
- 구매가 발생하면 가격·판매량을 추측하지 말고 Latpeed 화면에서 확인한 값만 기록

## 다음 제품 증거

실제 Supabase 테스트 프로젝트에서 `supabase test db`와 remote drift job을 통과시킨 CI 링크 또는 캡처를 만든다. 이 증거가 생기기 전에는 “실제 프로젝트 전체 검증 완료”라고 표현하지 않는다.
