/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // EDR 콘솔 팔레트: 다크 SOC 워룸 톤. 심각도 색상은 컴포넌트에서 직접 지정(팔레트 참고용)
        base: "#0B0F14",
        panel: "#131920",
        border: "#1F2933",
        critical: "#FF3B3B",
        high: "#FF8A3D",
        medium: "#FFD23D",
        info: "#3DA9FC",
        online: "#3DDC84",
      },
    },
  },
  plugins: [],
};
