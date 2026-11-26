/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        darkBg: '#0b0f19',
        cardBg: '#131b2e',
        cardBorder: '#1e293b',
        accentBlue: '#3b82f6',
        accentPurple: '#8b5cf6',
        safeGreen: '#10b981',
        warningYellow: '#f59e0b',
        dangerRed: '#ef4444',
      }
    },
  },
  plugins: [],
}
