import React from "react";
import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { GridBackdrop } from "../components/GridBackdrop";
import { theme, gradientText } from "../theme";

// 0:18–0:28 — 10s = 300 frames at 30fps.
// One bad actor → exponential agent fan-out → inbox flood.
export const Scene3AIScale: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleProgress = spring({
    frame: frame - 4,
    fps,
    config: { damping: 14, mass: 0.6, stiffness: 80 },
  });
  const titleY = interpolate(titleProgress, [0, 1], [40, 0]);
  const titleOpacity = interpolate(titleProgress, [0, 1], [0, 1]);

  // Bad actor scales in
  const actorProgress = spring({
    frame: frame - 30,
    fps,
    config: { damping: 12, mass: 0.6, stiffness: 80 },
  });
  const actorScale = interpolate(actorProgress, [0, 1], [0.4, 1]);
  const actorOpacity = interpolate(actorProgress, [0, 1], [0, 1]);

  // Number of spawned agents grows quickly
  const agentSpawnProgress = interpolate(frame, [60, 240], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const totalAgents = 240;
  const visibleAgents = Math.floor(
    interpolate(Math.pow(agentSpawnProgress, 1.6), [0, 1], [0, totalAgents])
  );

  const counterValue = Math.floor(
    interpolate(Math.pow(agentSpawnProgress, 1.4), [0, 1], [0, 4287])
  );

  const counterOpacity = interpolate(frame, [70, 100], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <AbsoluteFill>
      <GridBackdrop intensity={0.6} />
      <AbsoluteFill
        style={{
          alignItems: "center",
          paddingTop: 90,
          gap: 30,
        }}
      >
        <div
          style={{
            fontFamily: theme.fontDisplay,
            fontWeight: 700,
            fontSize: 64,
            letterSpacing: "0.005em",
            transform: `translateY(${titleY}px)`,
            opacity: titleOpacity,
            textAlign: "center",
            maxWidth: 1100,
            lineHeight: 1.18,
            ...gradientText,
          }}
        >
          AI agents accelerate spam
          <br />
          by orders of magnitude.
        </div>

        <div
          style={{
            position: "relative",
            width: 1100,
            height: 540,
            marginTop: 20,
          }}
        >
          {/* Bad actor in center */}
          <div
            style={{
              position: "absolute",
              left: "50%",
              top: 50,
              transform: `translate(-50%, 0) scale(${actorScale})`,
              opacity: actorOpacity,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 10,
            }}
          >
            <BadActorBadge />
            <div
              style={{
                fontFamily: theme.fontMono,
                fontSize: 12,
                letterSpacing: "0.2em",
                color: theme.textMuted,
                textTransform: "uppercase",
              }}
            >
              1 bad actor
            </div>
          </div>

          {/* Spawned agent dots */}
          <AgentSwarm count={visibleAgents} frame={frame} />

          {/* Counter */}
          <div
            style={{
              position: "absolute",
              right: 0,
              bottom: 0,
              opacity: counterOpacity,
              fontFamily: theme.fontMono,
              padding: "14px 22px",
              borderRadius: 14,
              background: "rgba(255, 107, 138, 0.10)",
              border: "1px solid rgba(255, 107, 138, 0.4)",
              color: "#ff6b8a",
              display: "flex",
              flexDirection: "column",
              gap: 4,
              minWidth: 240,
            }}
          >
            <span
              style={{
                fontSize: 11,
                letterSpacing: "0.22em",
                color: "rgba(255, 107, 138, 0.7)",
                textTransform: "uppercase",
              }}
            >
              fake agents spawned
            </span>
            <span
              style={{
                fontSize: 36,
                fontWeight: 700,
                fontVariantNumeric: "tabular-nums",
              }}
            >
              {counterValue.toLocaleString()}
            </span>
          </div>
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};

const BadActorBadge: React.FC = () => {
  return (
    <div
      style={{
        width: 96,
        height: 96,
        borderRadius: "50%",
        background:
          "radial-gradient(circle at 35% 30%, #ff8a9c, #b62a4e 70%, #5a0d22 100%)",
        boxShadow:
          "0 0 40px rgba(255, 107, 138, 0.55), inset 0 0 20px rgba(255,255,255,0.18)",
        border: "2px solid rgba(255, 107, 138, 0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <svg
        width="44"
        height="44"
        viewBox="0 0 24 24"
        fill="none"
        stroke="#1a0510"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
        <circle cx="12" cy="7" r="4" />
      </svg>
    </div>
  );
};

const AgentSwarm: React.FC<{ count: number; frame: number }> = ({
  count,
  frame,
}) => {
  const dots = React.useMemo(() => {
    const out: { x: number; y: number; delay: number }[] = [];
    let seed = 9001;
    const rand = () => {
      seed = (seed * 16807) % 2147483647;
      return seed / 2147483647;
    };
    // Place dots in a fan/cone radiating outward & downward from the actor
    for (let i = 0; i < 240; i += 1) {
      const angle = (rand() - 0.5) * Math.PI * 1.1; // -100° to +100° around vertical
      const distance = 110 + rand() * 320;
      const x = 50 + Math.sin(angle) * distance * 0.07;
      const y = 24 + Math.cos(angle * 0.8) * distance * 0.13;
      out.push({ x, y, delay: i });
    }
    return out;
  }, []);

  return (
    <>
      {dots.slice(0, count).map((d, i) => {
        const localFrame = frame - 60 - d.delay * 0.7;
        const popIn = interpolate(localFrame, [0, 8], [0, 1], {
          extrapolateLeft: "clamp",
          extrapolateRight: "clamp",
        });
        const float = Math.sin(frame / 14 + i) * 1.5;
        return (
          <div
            key={i}
            style={{
              position: "absolute",
              left: `${d.x}%`,
              top: `${d.y + float}%`,
              width: 14,
              height: 14,
              transform: `translate(-50%, -50%) scale(${popIn})`,
              borderRadius: "50%",
              background:
                "radial-gradient(circle at 35% 30%, #ff8a9c, #b62a4e)",
              boxShadow: "0 0 8px rgba(255, 107, 138, 0.6)",
              opacity: 0.85,
            }}
          />
        );
      })}
    </>
  );
};
