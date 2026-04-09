/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./pages/templates/**/*.html",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: "#4A8EC4",
          dark: "#3572A0",
        },
        surface: "#ffffff",
        bg: "#EEF5FB",
        border: "#D4E4F0",
        muted: "#6B7F96",
        error: {
          DEFAULT: "#c53030",
          bg: "#fff5f5",
          border: "#fed7d7",
        },
        success: {
          DEFAULT: "#276749",
          bg: "#f0fff4",
          border: "#9ae6b4",
        },
      },
      borderRadius: {
        DEFAULT: "8px",
      },
      boxShadow: {
        card: "0 2px 8px rgba(0, 0, 0, 0.08)",
        dropdown: "0 4px 16px rgba(0, 0, 0, 0.12)",
      },
    },
  },
  plugins: [],
}
