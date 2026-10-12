# 과제 8 패스키 적용 안내

## 현재 단계
기존 카드 1 수정본에 패스키 등록, 로그인, 로그아웃, 계정별 비공개 자료 조회, 패스키 목록과 삭제 기능을 추가했습니다.
공개 소개는 로그인 없이 열립니다. 비공개 자료는 DB에만 있으며 정적 배포 파일에는 없습니다.

## 적용 순서
1. Supabase pds-diary SQL Editor의 새 쿼리에서 sql/003_passkey_functions.sql 전체를 실행합니다.
   기존 계정·자료·등록권은 그대로 유지됩니다. 첫 테이블 생성 SQL과 등록권 발급 SQL은 다시 실행하지 않습니다.
2. 기존 my-intro-page 저장소의 루트에 이 묶음 안의 파일과 폴더를 올립니다.
   index.html, api, lib, scripts, sql, test, client.js, package.json, package-lock.json, vercel.json, README-T08.md.
   이미 존재하는 파일은 교체합니다. node_modules와 public은 올리지 않습니다.
3. Vercel 배포가 Ready가 될 때까지 기다립니다. package.json은 Node 22.x를 지정합니다.
   vercel.json의 Build Command는 npm run build, Output Directory는 public입니다.
4. 반드시 https://my-intro-page-nine.vercel.app/ 에서 등록합니다. 임의 Preview 주소는 허용하지 않습니다.
5. 나만의 작업실에서 owner-a를 선택하고 '첫 패스키 등록'을 펼칩니다.
   본인 메모의 owner-a 등록권과 이름을 입력하고 첫 패스키 등록을 누릅니다.
6. 기기 안내로 등록을 마친 다음 '패스키 로그인'을 누릅니다.
   로그인 후 예시 자료 세 개와 패스키 이름·등록일이 보여야 합니다.

## 최초 등록과 추가 등록
등록권은 최초 등록에만 사용합니다. 성공 시 DB 해시를 지워 재사용을 막습니다.
등록을 취소하면 패스키와 계정 등록 완료 상태를 저장하지 않습니다.
등록권 입력 칸은 비밀번호 칸이 아니며 로그인에 사용하지 않습니다.
등록권을 캡처하거나 공개 기록에 포함하지 마세요.
추가 등록은 로그인된 계정에서만 가능하며, 전달한 username으로 다른 계정에 추가할 수 없습니다.
계정 B의 최초 등록 전에는 A에서 로그아웃한 뒤 tester-b를 선택하고 B 등록권을 사용합니다.

## 서버 흐름
api/passkey.js?action=register-options 및 register-verify: 등록권/세션 확인, 질문 생성·검증, 공개키 저장.
api/passkey.js?action=login-options 및 login-verify: 질문 발급, 저장된 공개키로 서명 확인, 서버 세션 발급.
api/passkey.js?action=logout: 서버 세션 철회와 쿠키 삭제.
api/private.js: 서버 세션에서 account_id를 얻어 자료 조회. URL/본문의 accountId 또는 username은 무시.
/api/private?targetAccountId=다른계정UUID: 계정이 다르면 403. /api/private?itemId=자료UUID: 본인 소유가 아니면 403.
api/passkeys.js: 로그인한 계정의 패스키 이름·등록일·ID·기기 유형 목록.
api/passkey.js?action=delete: 로그인·소유권·마지막 키 검사를 통과한 키만 삭제. 모든 기존 세션 철회.
lib/security.cjs: 5분 질문 보관, 조건부 UPDATE로 일회용 소비, 1시간 세션 검증, 쿠키 및 Origin 검사.
sql/003_passkey_functions.sql: 계정 행 잠금으로 최초 등록·로그인·삭제 동시 요청을 처리.

## 저장 형식
public_key는 검증 라이브러리에서 얻은 COSE 공개키 바이트를 base64url 문자열로 인코딩한 값입니다.
개인키와 비밀번호는 저장하지 않습니다. 세션은 무작위 32바이트이며 DB에는 SHA-256 해시만 저장합니다.
쿠키는 HttpOnly, Secure, SameSite=Strict, __Host- 접두사입니다.

## 패스키 분실 정책
마지막 패스키 삭제는 409 LAST_PASSKEY로 거절합니다.
모든 키를 잃었을 때 셀프 복구는 없습니다. 운영자가 별도로 본인 확인 후 복구해야 하며 자동 복구 기능은 구현하지 않았습니다.
같은 동기화 패스키가 두 기기에 보이는 것을 두 개 등록으로 세지 않습니다. 서로 다른 credential_id가 필요합니다.

## 카드 2 남길 것
등록 요청·응답 (register-verify에는 등록권과 개인키가 없습니다), t08_passkeys의 공개키 저장 행, 로그인 후 패스키 목록 화면.
패스키 저장 위치는 실제 기기 창에서 선택한 Google 비밀번호 관리자 / Windows Hello / 보안 키 등을 직접 기록합니다.
로그인 쿠키·등록권·토큰은 증빙에서 가립니다.

## 로컬 검증
npm install
npm test
npm run build
9개 검사가 통과했습니다. 암호화 서명은 실제 라이브러리로 검증하지만 DB 경로는 모의 응답으로 검사했습니다.
실제 Supabase 함수 실행과 브라우저의 기기 인증 창은 배포 후 확인해야 합니다.

## 남은 제한
자동 본인 확인 및 분실 복구, 요청 횟수 제한과 오래된 질문/세션 자동 청소는 구현하지 않았습니다.
로그인된 기기를 다른 사람이 조작하거나 같은 출처에 XSS가 생기는 상황은 패스키만으로 막을 수 없습니다.
기존 소개의 인물 사진·LinkedIn 캡처는 최종 제출의 개인정보 제외 조건과 함께 검토해야 합니다.
