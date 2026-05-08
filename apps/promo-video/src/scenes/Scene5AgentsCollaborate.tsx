import React from "react";
import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { GridBackdrop } from "../components/GridBackdrop";
import {
  AgentAvatar,
  MessageBubble,
} from "../components/MessageBubble";
import { theme, gradientText } from "../theme";

// 12s = 360 frames at 30fps. Two agents, autonomously exchanging messages
// over the spam-free foundation we just established.
interface Exchange {
  side: "left" | "right";
  text: string;
  enter: number; // frame when bubble starts entering
  settle: number; // frame when bubble has finished entering
  status?: string; // optional status badge that follows the bubble
}

const EXCHANGES: Exchange[] = [
  {
    side: "left",
    text: "Free Mon 2pm or Tue 11am for a 30-min demo?",
    enter: 60,
    settle: 80,
    status: "Auto-sent",
  },
  {
    side: "right",
    text: "Mon 2pm works. Sending the calendar invite now.",
    enter: 130,
    settle: 150,
    status: "Auto-replied",
  },
  {
    side: "left",
    text: "Confirmed. Logged in your human's inbox.",
    enter: 200,
    settle: 220,
    status: "Logged for review",
  },
];

const SCENE_DURATION = 360;
const FOOTER_FADE_IN = 280;

export const Scene5AgentsCollaborate: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleProgress = spring({
    frame: frame - 4,
    fps,
    config: { damping: 14, mass: 0.6, stiffness: 80 },
  });
  const titleY = interpolate(titleProgress, [0, 1], [40, 0]);
  const titleOpacity = interpolate(titleProgress, [0, 1], [0, 1]);

  const avatarsProgress = spring({
    frame: frame - 26,
    fps,
    config: { damping: 16, mass: 0.7, stiffness: 80 },
  });
  const avatarsOpacity = interpolate(avatarsProgress, [0, 1], [0, 1]);
  const avatarsY = interpolate(avatarsProgress, [0, 1], [20, 0]);

  // Determine which avatar is "active" (last to send/receive)
  const activeSide = (() => {
    let last: "left" | "right" | null = null;
    for (const ex of EXCHANGES) {
      if (frame >= ex.enter) last = ex.side;
    }
    return last;
  })();

  const footerOpacity = interpolate(
    frame,
    [FOOTER_FADE_IN, FOOTER_FADE_IN + 25],
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
          gap: 24,
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
            ...gradientText,
          }}
        >
          Now your agents can talk.
        </div>

        <div
          style={{
            position: "relative",
            width: 1300,
            height: 600,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            paddingTop: 40,
            transform: `translateY(${avatarsY}px)`,
            opacity: avatarsOpacity,
          }}
        >
          <AgentAvatar
            side="left"
            label="Your agent"
            active={activeSide === "left"}
          />
          <AgentAvatar
            side="right"
            label="Their agent"
            active={activeSide === "right"}
          />

          {/* Conversation column in the middle */}
          <div
            style={{
              position: "absolute",
              left: "50%",
              top: 30,
              transform: "translateX(-50%)",
              width: 720,
              display: "flex",
              flexDirection: "column",
              gap: 16,
            }}
          >
            {EXCHANGES.map((ex, i) => (
              <BubbleRow key={i} exchange={ex} frame={frame} />
            ))}
          </div>
        </div>

        <div
          style={{
            position: "absolute",
            bottom: 70,
            left: "50%",
            transform: "translateX(-50%)",
            opacity: footerOpacity,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 14,
          }}
        >
          <div
            style={{
              fontFamily: theme.fontMono,
              fontSize: 14,
              letterSpacing: "0.22em",
              color: theme.green,
              textTransform: "uppercase",
              padding: "8px 18px",
              borderRadius: 999,
              background: "rgba(93, 240, 165, 0.10)",
              border: `1px solid rgba(93, 240, 165, 0.35)`,
            }}
          >
            ✓ Routine handled · Bigger calls escalate to you
          </div>
          <div
            style={{
              fontFamily: theme.fontDisplay,
              fontSize: 24,
              color: theme.textMuted,
              letterSpacing: "0.01em",
            }}
          >
            You step in when it counts. Not before.
          </div>
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};

const BubbleRow: React.FC<{ exchange: Exchange; frame: number }> = ({
  exchange,
  frame,
}) => {
  const localFrame = frame - exchange.enter;
  if (localFrame < 0) return null;

  const settleDuration = exchange.settle - exchange.enter;
  const enterT = interpolate(localFrame, [0, settleDuration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  const slideFrom = exchange.side === "left" ? -180 : 180;
  const x = interpolate(enterT, [0, 1], [slideFrom, 0]);
  const opacity = interpolate(enterT, [0, 1], [0, 1]);

  // Status badge fades in shortly after settle
  const statusOpacity = interpolate(
    localFrame,
    [settleDuration + 5, settleDuration + 22],
    [0, 1],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
  );

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: exchange.side === "left" ? "flex-start" : "flex-end",
        gap: 6,
        transform: `translateX(${x}px)`,
        opacity,
      }}
    >
      <MessageBubble
        text={exchange.text}
        side={exchange.side}
        width={520}
      />
      {exchange.status ? (
        <div
          style={{
            opacity: statusOpacity,
            fontFamily: theme.fontMono,
            fontSize: 11,
            letterSpacing: "0.18em",
            color: theme.green,
            textTransform: "uppercase",
            paddingLeft: exchange.side === "left" ? 6 : 0,
            paddingRight: exchange.side === "right" ? 6 : 0,
          }}
        >
          ✓ {exchange.status}
        </div>
      ) : null}
    </div>
  );
};

export { SCENE_DURATION as SCENE5_DURATION };
