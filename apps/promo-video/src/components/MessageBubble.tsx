import React from "react";
import { theme } from "../theme";

interface MessageBubbleProps {
  text: string;
  side: "left" | "right";
  scale?: number;
  width?: number;
  encrypted?: boolean;
}

export const MessageBubble: React.FC<MessageBubbleProps> = ({
  text,
  side,
  scale = 1,
  width = 380,
  encrypted = true,
}) => {
  const isLeft = side === "left";
  const accent = isLeft ? theme.cyan : theme.lavender;

  return (
    <div
      style={{
        width: width * scale,
        padding: `${14 * scale}px ${18 * scale}px`,
        borderRadius: 16 * scale,
        borderTopLeftRadius: isLeft ? 4 : 16 * scale,
        borderTopRightRadius: isLeft ? 16 * scale : 4,
        background: isLeft
          ? "rgba(125, 215, 255, 0.10)"
          : "rgba(182, 148, 255, 0.10)",
        border: `1px solid ${isLeft ? "rgba(125, 215, 255, 0.35)" : "rgba(182, 148, 255, 0.35)"}`,
        boxShadow: `0 8px 28px rgba(0, 0, 0, 0.35)`,
        backdropFilter: "blur(8px)",
        fontFamily: theme.fontDisplay,
        color: theme.text,
        fontSize: 18 * scale,
        lineHeight: 1.4,
        position: "relative",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 6 * scale,
          fontFamily: theme.fontMono,
          fontSize: 10 * scale,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          color: accent,
        }}
      >
        {encrypted ? (
          <svg
            width={11 * scale}
            height={11 * scale}
            viewBox="0 0 24 24"
            fill="none"
            stroke={accent}
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        ) : null}
        <span>{isLeft ? "Your agent" : "Their agent"}</span>
        <span style={{ color: theme.textDim }}>·</span>
        <span style={{ color: theme.textDim }}>E2E</span>
      </div>
      <div>{text}</div>
    </div>
  );
};

export const AgentAvatar: React.FC<{
  side: "left" | "right";
  label: string;
  scale?: number;
  active?: boolean;
}> = ({ side, label, scale = 1, active = false }) => {
  const isLeft = side === "left";
  const accent = isLeft ? theme.cyan : theme.lavender;
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 8 * scale,
      }}
    >
      <div
        style={{
          width: 88 * scale,
          height: 88 * scale,
          borderRadius: "50%",
          background: isLeft
            ? `linear-gradient(135deg, ${theme.cyan}, ${theme.lavender})`
            : `linear-gradient(135deg, ${theme.lavender}, ${theme.pink})`,
          boxShadow: active
            ? `0 0 30px ${accent}, 0 0 8px ${accent}`
            : `0 0 18px rgba(140, 160, 255, 0.3)`,
          border: `2px solid ${active ? accent : "rgba(140, 160, 255, 0.4)"}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          transition: "box-shadow 100ms",
        }}
      >
        <svg
          width={40 * scale}
          height={40 * scale}
          viewBox="0 0 24 24"
          fill="none"
          stroke={theme.bg}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <rect x="3" y="11" width="18" height="10" rx="2" />
          <circle cx="12" cy="5" r="2" />
          <path d="M12 7v4" />
          <line x1="8" y1="16" x2="8" y2="16" />
          <line x1="16" y1="16" x2="16" y2="16" />
        </svg>
      </div>
      <div
        style={{
          fontFamily: theme.fontMono,
          fontSize: 11 * scale,
          letterSpacing: "0.16em",
          textTransform: "uppercase",
          color: theme.textMuted,
        }}
      >
        {label}
      </div>
    </div>
  );
};
