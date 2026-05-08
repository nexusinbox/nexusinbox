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

// 0:28–0:46 — 18s = 540 frames. Solution: World ID anchor → fan-out of agents
// → single block on the human → all agents disappear.
const BLOCK_FRAME = 360; // when the user blocks the World ID
const VANISH_FRAMES = 60;

export const Scene4HumanBlock: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleProgress = spring({
    frame: frame - 4,
    fps,
    config: { damping: 14, mass: 0.6, stiffness: 80 },
  });
  const titleY = interpolate(titleProgress, [0, 1], [40, 0]);
  const titleOpacity = interpolate(titleProgress, [0, 1], [0, 1]);

  // World ID circle reveal
  const widProgress = spring({
    frame: frame - 30,
    fps,
    config: { damping: 16, mass: 0.7, stiffness: 70 },
  });
  const widScale = interpolate(widProgress, [0, 1], [0.4, 1]);
  const widOpacity = interpolate(widProgress, [0, 1], [0, 1]);

  // Spokes appear one by one
  const SPOKE_COUNT = 8;
  const SPOKE_START = 90;

  // Block highlight on the World ID
  const blockHighlight = interpolate(
    frame,
    [BLOCK_FRAME - 18, BLOCK_FRAME, BLOCK_FRAME + 8],
    [0, 1, 0],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
  );

  const blocked = frame >= BLOCK_FRAME;
  const stampProgress = spring({
    frame: frame - BLOCK_FRAME,
    fps,
    config: { damping: 9, mass: 0.5, stiffness: 140 },
  });

  const allClearOpacity = interpolate(
    frame,
    [BLOCK_FRAME + VANISH_FRAMES + 6, BLOCK_FRAME + VANISH_FRAMES + 30],
    [0, 1],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
  );

  return (
    <AbsoluteFill>
      <GridBackdrop intensity={0.7} />
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
            fontSize: 72,
            letterSpacing: "0.005em",
            transform: `translateY(${titleY}px)`,
            opacity: titleOpacity,
            ...gradientText,
          }}
        >
          Block at the human level.
        </div>

        <div
          style={{
            position: "relative",
            width: 800,
            height: 580,
          }}
        >
          {/* Spokes (lines + agent dots) */}
          {Array.from({ length: SPOKE_COUNT }).map((_, i) => (
            <Spoke
              key={i}
              index={i}
              total={SPOKE_COUNT}
              startFrame={SPOKE_START + i * 7}
              blockFrame={BLOCK_FRAME}
              frame={frame}
            />
          ))}

          {/* Central World ID badge */}
          <div
            style={{
              position: "absolute",
              left: "50%",
              top: "50%",
              transform: `translate(-50%, -50%) scale(${widScale})`,
              opacity: widOpacity,
            }}
          >
            <WorldIDBadge
              highlight={blockHighlight}
              blocked={blocked}
              stampProgress={stampProgress}
            />
          </div>

          {/* All clear text */}
          <div
            style={{
              position: "absolute",
              left: "50%",
              bottom: -20,
              transform: "translate(-50%, 0)",
              opacity: allClearOpacity,
              fontFamily: theme.fontMono,
              fontSize: 18,
              letterSpacing: "0.18em",
              color: theme.green,
              textTransform: "uppercase",
              padding: "8px 18px",
              borderRadius: 999,
              background: "rgba(93, 240, 165, 0.10)",
              border: `1px solid rgba(93, 240, 165, 0.4)`,
              whiteSpace: "nowrap",
            }}
          >
            All agents disabled · 0 fake agents
          </div>
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};

const Spoke: React.FC<{
  index: number;
  total: number;
  startFrame: number;
  blockFrame: number;
  frame: number;
}> = ({ index, total, startFrame, blockFrame, frame }) => {
  const angle = (index / total) * Math.PI * 2 - Math.PI / 2;
  const distance = 230;
  const x = 50 + (Math.cos(angle) * distance) / 8;
  const y = 50 + (Math.sin(angle) * distance) / 5.8;

  // Line draw-in
  const drawIn = interpolate(frame, [startFrame, startFrame + 18], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Stagger vanish slightly per spoke
  const vanishOffset = index * 2;
  const vanishStart = blockFrame + vanishOffset;
  const localVanish = interpolate(
    frame,
    [vanishStart, vanishStart + 22],
    [0, 1],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
  );
  const opacity = (1 - localVanish) * drawIn;
  const dotScale = (1 - localVanish) * drawIn;

  return (
    <>
      {/* Connecting line */}
      <svg
        style={{
          position: "absolute",
          inset: 0,
          width: "100%",
          height: "100%",
          pointerEvents: "none",
          opacity,
        }}
      >
        <line
          x1="50%"
          y1="50%"
          x2={`${x}%`}
          y2={`${y}%`}
          stroke={theme.cyan}
          strokeOpacity={0.5}
          strokeWidth={1.5}
          strokeDasharray="6 8"
          strokeDashoffset={(1 - drawIn) * 100}
        />
      </svg>

      {/* Agent dot */}
      <div
        style={{
          position: "absolute",
          left: `${x}%`,
          top: `${y}%`,
          transform: `translate(-50%, -50%) scale(${dotScale})`,
          opacity,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 6,
        }}
      >
        <div
          style={{
            width: 56,
            height: 56,
            borderRadius: "50%",
            background: `linear-gradient(135deg, ${theme.cyan}, ${theme.lavender})`,
            boxShadow: `0 0 20px rgba(125, 215, 255, 0.45)`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <svg
            width="26"
            height="26"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#0a0c18"
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
            fontSize: 11,
            letterSpacing: "0.1em",
            color: theme.textMuted,
          }}
        >
          agent #{(1234 + index * 91).toString().slice(-4)}
        </div>
      </div>
    </>
  );
};

const WorldIDBadge: React.FC<{
  highlight: number;
  blocked: boolean;
  stampProgress: number;
}> = ({ highlight, blocked, stampProgress }) => {
  const borderColor = blocked ? theme.red : theme.cyan;
  const iconStroke = blocked ? "rgba(255, 107, 138, 0.55)" : theme.cyan;
  const labelColor = blocked ? "rgba(255, 107, 138, 0.85)" : theme.textMuted;
  const labelText = blocked ? "World ID · Blocked" : "World ID · Verified";
  const stampScale = 0.6 + Math.min(stampProgress, 1) * 0.5;
  const stampRotation = -10 + (1 - Math.min(stampProgress, 1)) * 18;

  return (
    <div
      style={{
        position: "relative",
        width: 180,
        height: 180,
        borderRadius: "50%",
        background: blocked
          ? "radial-gradient(circle at 35% 30%, rgba(255, 107, 138, 0.18), rgba(255, 107, 138, 0.04) 60%, transparent 100%)"
          : "radial-gradient(circle at 35% 30%, rgba(255,255,255,0.16), rgba(125,215,255,0.05) 60%, transparent 100%)",
        border: `2px solid ${borderColor}`,
        filter: blocked ? "saturate(0.85)" : "none",
        boxShadow: `
          0 0 60px ${blocked ? "rgba(255, 107, 138, 0.45)" : `rgba(125, 215, 255, ${0.35 + highlight * 0.5})`},
          inset 0 0 24px rgba(255, 255, 255, 0.1),
          ${highlight > 0 ? `0 0 0 ${highlight * 14}px rgba(255, 107, 138, 0.18)` : "0 0 0 0 transparent"}
        `,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 8,
      }}
    >
      <svg
        width="56"
        height="56"
        viewBox="0 0 24 24"
        fill="none"
        stroke={iconStroke}
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="12" cy="12" r="10" />
        <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
        <path d="M2 12h20" />
      </svg>
      <div
        style={{
          fontFamily: theme.fontMono,
          fontSize: 10,
          letterSpacing: "0.22em",
          color: labelColor,
          textTransform: "uppercase",
        }}
      >
        {labelText}
      </div>

      {/* Block flash ring (frame around the moment of blocking) */}
      {highlight > 0 ? (
        <div
          style={{
            position: "absolute",
            inset: -8,
            borderRadius: "50%",
            border: `2px solid ${theme.red}`,
            opacity: highlight,
            pointerEvents: "none",
          }}
        />
      ) : null}

      {/* Red X cross drawn through the badge */}
      {blocked ? (
        <svg
          style={{
            position: "absolute",
            inset: 0,
            width: "100%",
            height: "100%",
            pointerEvents: "none",
            opacity: Math.min(stampProgress * 1.4, 1),
          }}
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
        >
          <line
            x1="22"
            y1="22"
            x2="78"
            y2="78"
            stroke={theme.red}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray="100"
            strokeDashoffset={(1 - Math.min(stampProgress, 1)) * 100}
          />
          <line
            x1="78"
            y1="22"
            x2="22"
            y2="78"
            stroke={theme.red}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray="100"
            strokeDashoffset={(1 - Math.min(stampProgress, 1)) * 100}
          />
        </svg>
      ) : null}

      {/* "BLOCKED" stamp dropping onto the badge */}
      {blocked ? (
        <div
          style={{
            position: "absolute",
            top: "50%",
            left: "50%",
            transform: `translate(-50%, -50%) scale(${stampScale}) rotate(${stampRotation}deg)`,
            opacity: Math.min(stampProgress * 1.2, 1),
            padding: "4px 14px",
            borderRadius: 4,
            border: `2px solid ${theme.red}`,
            background: "rgba(10, 12, 24, 0.85)",
            color: theme.red,
            fontFamily: theme.fontMono,
            fontWeight: 700,
            fontSize: 16,
            letterSpacing: "0.28em",
            textTransform: "uppercase",
            whiteSpace: "nowrap",
            pointerEvents: "none",
          }}
        >
          Blocked
        </div>
      ) : null}
    </div>
  );
};
