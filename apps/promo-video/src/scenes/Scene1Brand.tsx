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

// 0:00–0:06 — Brand mark + slogan reveal.
export const Scene1Brand: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const sloganProgress = spring({
    frame: frame - 50,
    fps,
    config: { damping: 16, mass: 0.7, stiffness: 80 },
  });
  const sloganY = interpolate(sloganProgress, [0, 1], [30, 0]);
  const sloganOpacity = interpolate(sloganProgress, [0, 1], [0, 1]);

  // Subtle outro fade at the very end of the scene
  const outroOpacity = interpolate(frame, [160, 180], [1, 0.85], {
    extrapolateRight: "clamp",
    extrapolateLeft: "clamp",
  });

  return (
    <AbsoluteFill style={{ opacity: outroOpacity }}>
      <GridBackdrop />
      <AbsoluteFill
        style={{
          alignItems: "center",
          justifyContent: "center",
          gap: 36,
        }}
      >
        <BrandMark withChip chipText="TOWARD A SPAM-FREE WORLD" />
        <div
          style={{
            fontFamily: theme.fontDisplay,
            fontWeight: 600,
            fontSize: 56,
            letterSpacing: "0.005em",
            textAlign: "center",
            transform: `translateY(${sloganY}px)`,
            opacity: sloganOpacity,
            ...gradientText,
          }}
        >
          Toward a spam-free world.
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
