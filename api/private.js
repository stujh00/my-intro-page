// 카드 1: 인증을 연결하기 전에는 모든 요청을 거절합니다.
// 카드 3에서 서버 세션 검증과 인증된 계정별 자료 조회로 교체합니다.
module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.status(401).json({ error: 'AUTH_REQUIRED', message: '패스키 로그인이 필요합니다.' });
};
