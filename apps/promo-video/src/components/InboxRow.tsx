import React from "react";
import { theme } from "../theme";

interface InboxRowProps {
  sender: string;
  subject: string;
  preview: string;
  spam?: boolean;
  blocked?: boolean;
  scale?: number;
  width?: number;
}

export const InboxRow: React.FC<InboxRowProps> = ({
  sender,
  subject,
  preview,
  spam = false,
  blocked = false,
  scale = 1,
  width = 760,
}) => {
  return (
    <div
      style={{
        position: "relative",
        width: width * scale,
        padding: `${20 * scale}px ${24 * scale}px`,
        borderRadius: 16 * scale,
        background: blocked
          ? "rgba(255, 107, 138, 0.08)"
          : "rgba(12, 16, 32, 0.78)",
        border: `1px solid ${blocked ? "rgba(255, 107, 138, 0.4)" : theme.borderSoft}`,
        backdropFilter: "blur(10px)",
        boxShadow: blocked
          ? `0 0 30px rgba(255, 107, 138, 0.18)`
          : `0 6px 28px rgba(0, 0, 0, 0.32)`,
        display: "flex",
        gap: 16 * scale,
        alignItems: "center",
        fontFamily: theme.fontDisplay,
        color: theme.text,
      }}
    >
      <div
        style={{
          width: 44 * scale,
          height: 44 * scale,
          borderRadius: "50%",
          background: spam
            ? "linear-gradient(135deg, #ff6b8a, #b694ff)"
            : `linear-gradient(135deg, ${theme.cyan}, ${theme.lavender})`,
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 20 * scale,
          fontWeight: 700,
          color: "#0a0c18",
        }}
      >
        {sender.charAt(0).toUpperCase()}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "baseline",
            marginBottom: 4 * scale,
          }}
        >
          <span
            style={{
              fontWeight: 700,
              fontSize: 18 * scale,
              color: theme.text,
            }}
          >
            {sender}
          </span>
          {spam ? (
            <span
              style={{
                fontFamily: theme.fontMono,
                fontSize: 11 * scale,
                letterSpacing: "0.18em",
                padding: `2px 10px`,
                borderRadius: 999,
                background: "rgba(255, 107, 138, 0.18)",
                color: "#ff6b8a",
                border: "1px solid rgba(255, 107, 138, 0.4)",
              }}
            >
              SPAM
            </span>
          ) : null}
        </div>
        <div
          style={{
            fontWeight: 600,
            fontSize: 17 * scale,
            color: blocked ? theme.textDim : theme.text,
            textDecoration: blocked ? "line-through" : "none",
            marginBottom: 3 * scale,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {subject}
        </div>
        <div
          style={{
            fontSize: 14 * scale,
            color: theme.textMuted,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {preview}
        </div>
      </div>
      {blocked ? (
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            pointerEvents: "none",
          }}
        >
          <div
            style={{
              fontFamily: theme.fontMono,
              fontSize: 14 * scale,
              letterSpacing: "0.3em",
              color: "#ff6b8a",
              padding: `8px 18px`,
              borderRadius: 8,
              background: "rgba(10, 12, 24, 0.75)",
              border: "1px solid rgba(255, 107, 138, 0.5)",
            }}
          >
            BLOCKED
          </div>
        </div>
      ) : null}
    </div>
  );
};
