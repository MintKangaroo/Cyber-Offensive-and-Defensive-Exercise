/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // 전술 지휘통제 HUD 팔레트(02번 문서). Red=앰버/레드, Blue=시안, 유출=마젠타.
        base: "#0A0E1A",
        panel: "#111725",
        border: "#1E2A3F",
        redteam: "#F5A623",
        redalert: "#FF4D4D",
        blueteam: "#22D3EE",
        flagmagenta: "#E84BC9",
        textmain: "#E8EDF5",
        textmuted: "#6B7A99",
      },
    },
  },
  plugins: [],
};
