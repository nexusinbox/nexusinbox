import React from "react";
import { AbsoluteFill, useCurrentFrame } from "remotion";
import { theme } from "../theme";

export const GridBackdrop: React.FC<{ intensity?: number }> = ({
  intensity = 1,
}) => {
  const frame = useCurrentFrame();
  const drift = (frame * 0.3) % 80;

  return (
    <AbsoluteFill style={{ background: theme.bg }}>
      {/* Perspective grid (floor) */}
      <AbsoluteFill
        style={{
          opacity: 0.35 * intensity,
          backgroundImage: `
            linear-gradient(rgba(140, 160, 255, 0.18) 1px, transparent 1px),
            linear-gradient(90deg, rgba(140, 160, 255, 0.18) 1px, transparent 1px)
          `,
          backgroundSize: "80px 80px",
          backgroundPosition: `0 ${drift}px, ${drift}px 0`,
          transform: "perspective(900px) rotateX(60deg) translateY(20%) scale(2)",
          transformOrigin: "50% 100%",
          maskImage:
            "radial-gradient(ellipse at 50% 100%, #000 30%, transparent 75%)",
          WebkitMaskImage:
            "radial-gradient(ellipse at 50% 100%, #000 30%, transparent 75%)",
        }}
      />
      {/* Soft cyan glow at bottom */}
      <AbsoluteFill
        style={{
          background:
            "radial-gradient(ellipse at 50% 110%, rgba(125, 215, 255, 0.12) 0%, transparent 60%)",
        }}
      />
      {/* Stars */}
      <Stars count={80} />
    </AbsoluteFill>
  );
};

const Stars: React.FC<{ count: number }> = ({ count }) => {
  const frame = useCurrentFrame();
  // Deterministic pseudo-random starfield (no seeded lib needed)
  const stars = React.useMemo(() => {
    const out: { x: number; y: number; size: number; phase: number }[] = [];
    let seed = 1337;
    const rand = () => {
      seed = (seed * 16807) % 2147483647;
      return seed / 2147483647;
    };
    for (let i = 0; i < count; i += 1) {
      out.push({
        x: rand() * 100,
        y: rand() * 100,
        size: 0.6 + rand() * 1.6,
        phase: rand() * Math.PI * 2,
      });
    }
    return out;
  }, [count]);

  return (
    <AbsoluteFill>
      {stars.map((s, i) => {
        const twinkle = 0.4 + 0.6 * (0.5 + 0.5 * Math.sin(frame / 18 + s.phase));
        return (
          <div
            key={i}
            style={{
              position: "absolute",
              left: `${s.x}%`,
              top: `${s.y}%`,
              width: s.size,
              height: s.size,
              borderRadius: "50%",
              background: theme.text,
              opacity: twinkle * 0.8,
              boxShadow: `0 0 ${s.size * 4}px rgba(232, 236, 255, 0.6)`,
            }}
          />
        );
      })}
    </AbsoluteFill>
  );
};
