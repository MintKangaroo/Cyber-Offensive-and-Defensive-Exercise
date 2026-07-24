/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // 클래식 SOC 콘솔 팔레트. Live Fire(전술HUD)/EDR(터미널)와 톤을 구분해
        // "정보 밀도가 최우선인 로그 분석 도구"라는 느낌을 준다.
        base: "#0A1119",
        panel: "#0E1620",
        border: "#22303F",
        info: "#5FA8D3",
        medium: "#D9A441",
        high: "#E0703A",
        critical: "#D64545",
        good: "#3FBF7F",
      },
    },
  },
  plugins: [],
};
