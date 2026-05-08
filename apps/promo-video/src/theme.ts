export const theme = {
  bg: "#0a0c18",
  bgDeeper: "#06080f",
  text: "#e8ecff",
  textMuted: "#9aa7d9",
  textDim: "#5a6590",
  border: "rgba(140, 160, 255, 0.18)",
  borderSoft: "rgba(140, 160, 255, 0.12)",
  panel: "rgba(12, 16, 32, 0.72)",
  cyan: "#7dd7ff",
  purple: "#b694ff",
  lavender: "#a9b8ff",
  green: "#5df0a5",
  pink: "#ff9ee0",
  red: "#ff6b8a",
  fontDisplay: '"SF Pro Display", "Helvetica Neue", system-ui, sans-serif',
  fontMono: '"SFMono-Regular", "JetBrains Mono", ui-monospace, monospace',
} as const;

export const gradientText: React.CSSProperties = {
  background: `linear-gradient(135deg, #ffffff 0%, ${theme.lavender} 50%, ${theme.cyan} 100%)`,
  WebkitBackgroundClip: "text",
  backgroundClip: "text",
  WebkitTextFillColor: "transparent",
  color: "transparent",
  filter: `drop-shadow(0 0 22px rgba(125, 215, 255, 0.25))`,
};
