import React from "react";
import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { GridBackdrop } from "../components/GridBackdrop";
import { BrandMark } from "../components/BrandMark";
import { theme, gradientText } from "../theme";

// 0:58–1:07 — 9s = 270 frames. Brand wrap-up + URL + CTA button.
export const Scene6CTA: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const sloganProgress = spring({
    frame: frame - 35,
    fps,
    config: { damping: 16, mass: 0.7, stiffness: 70 },
  });
  const sloganY = interpolate(sloganProgress, [0, 1], [30, 0]);
  const sloganOpacity = interpolate(sloganProgress, [0, 1], [0, 1]);

  const ctaProgress = spring({
    frame: frame - 80,
    fps,
    config: { damping: 16, mass: 0.7, stiffness: 70 },
  });
  const ctaScale = interpolate(ctaProgress, [0, 1], [0.85, 1]);
  const ctaOpacity = interpolate(ctaProgress, [0, 1], [0, 1]);

  const urlOpacity = interpolate(frame, [110, 130], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <AbsoluteFill>
      <GridBackdrop />
      <AbsoluteFill
        style={{
          alignItems: "center",
          justifyContent: "center",
          gap: 32,
        }}
      >
        <BrandMark withChip={false} size={0.85} />

        <div
          style={{
            fontFamily: theme.fontDisplay,
            fontWeight: 600,
            fontSize: 48,
            letterSpacing: "0.005em",
            transform: `translateY(${sloganY}px)`,
            opacity: sloganOpacity,
            ...gradientText,
          }}
        >
          Toward a spam-free world.
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 18,
            transform: `scale(${ctaScale})`,
            opacity: ctaOpacity,
          }}
        >
          <button
            style={{
              padding: "20px 44px",
              borderRadius: 999,
              border: "none",
              background: `linear-gradient(135deg, ${theme.cyan}, ${theme.lavender})`,
              boxShadow: `0 0 40px rgba(125, 215, 255, 0.4)`,
              fontFamily: theme.fontDisplay,
              fontWeight: 700,
              fontSize: 22,
              letterSpacing: "0.04em",
              color: theme.bg,
              display: "inline-flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <svg
              width="22"
              height="22"
              viewBox="0 0 24 24"
              fill="none"
              stroke={theme.bg}
              strokeWidth="2.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
              <path d="M2 12h20" />
            </svg>
            Get your Agent Address
          </button>
          <div
            style={{
              fontFamily: theme.fontMono,
              fontSize: 12,
              letterSpacing: "0.22em",
              color: theme.textDim,
              textTransform: "uppercase",
            }}
          >
            Verified by World ID
          </div>
          <div
            style={{
              opacity: urlOpacity,
              fontFamily: theme.fontMono,
              fontSize: 18,
              letterSpacing: "0.18em",
              color: theme.textMuted,
              textTransform: "uppercase",
              marginTop: 4,
            }}
          >
            app.nexusinbox.ai
          </div>
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
