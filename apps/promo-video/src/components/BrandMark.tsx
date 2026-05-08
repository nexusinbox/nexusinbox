import React from "react";
import { interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { theme, gradientText } from "../theme";

interface BrandMarkProps {
  size?: number;
  delay?: number;
  withChip?: boolean;
  chipText?: string;
}

export const BrandMark: React.FC<BrandMarkProps> = ({
  size = 1,
  delay = 0,
  withChip = true,
  chipText = "TOWARD A SPAM-FREE WORLD",
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const localFrame = frame - delay;
  const chipOpacity = interpolate(localFrame, [0, 18], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const titleProgress = spring({
    frame: localFrame - 6,
    fps,
    config: { damping: 14, mass: 0.6, stiffness: 80 },
  });
  const titleY = interpolate(titleProgress, [0, 1], [40, 0]);
  const titleOpacity = interpolate(titleProgress, [0, 1], [0, 1]);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 18 * size,
      }}
    >
      {withChip ? (
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 10,
            padding: `${8 * size}px ${18 * size}px`,
            border: `1px solid ${theme.border}`,
            borderRadius: 999,
            background: "rgba(12, 16, 32, 0.55)",
            backdropFilter: "blur(8px)",
            fontFamily: theme.fontMono,
            fontSize: 14 * size,
            letterSpacing: "0.18em",
            color: theme.textMuted,
            textTransform: "uppercase",
            opacity: chipOpacity,
          }}
        >
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: 4,
              background: theme.green,
              boxShadow: `0 0 10px ${theme.green}`,
            }}
          />
          {chipText}
        </div>
      ) : null}
      <div
        style={{
          fontFamily: theme.fontDisplay,
          fontWeight: 800,
          fontSize: 120 * size,
          letterSpacing: "0.04em",
          lineHeight: 1,
          textAlign: "center",
          transform: `translateY(${titleY}px)`,
          opacity: titleOpacity,
          ...gradientText,
        }}
      >
        <div>NEXUS</div>
        <div>INBOX</div>
      </div>
    </div>
  );
};
