import React from "react";
import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { GridBackdrop } from "../components/GridBackdrop";
import { InboxRow } from "../components/InboxRow";
import { theme, gradientText } from "../theme";

interface SpamBeat {
  enter: number;
  block: number;
  exit: number;
  sender: string;
  subject: string;
  preview: string;
}

// 0:06–0:18 — 12s = 360 frames at 30fps. The block animation ramps up.
const BEATS: SpamBeat[] = [
  {
    enter: 30,
    block: 75,
    exit: 110,
    sender: "DealsHQ",
    subject: "URGENT: Claim your reward now",
    preview: "click this link to receive...",
  },
  {
    enter: 110,
    block: 145,
    exit: 175,
    sender: "rewards-bot-921",
    subject: "Free crypto airdrop waiting",
    preview: "verify your wallet to unlock...",
  },
  {
    enter: 175,
    block: 200,
    exit: 225,
    sender: "no-reply-9281",
    subject: "Your invoice is overdue",
    preview: "we will charge your card unless...",
  },
  {
    enter: 225,
    block: 247,
    exit: 268,
    sender: "support-team-44",
    subject: "Action required: confirm identity",
    preview: "click below to keep your account...",
  },
  {
    enter: 268,
    block: 285,
    exit: 304,
    sender: "winner-notify",
    subject: "Congratulations! You've been selected",
    preview: "claim your prize within 24 hours...",
  },
  {
    enter: 304,
    block: 318,
    exit: 335,
    sender: "promo-72e1",
    subject: "Limited time: 90% off",
    preview: "today only, do not miss out...",
  },
];

export const Scene2Whackamole: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleProgress = spring({
    frame: frame - 4,
    fps,
    config: { damping: 14, mass: 0.6, stiffness: 80 },
  });
  const titleY = interpolate(titleProgress, [0, 1], [40, 0]);
  const titleOpacity = interpolate(titleProgress, [0, 1], [0, 1]);

  return (
    <AbsoluteFill>
      <GridBackdrop intensity={0.7} />
      <AbsoluteFill
        style={{
          alignItems: "center",
          paddingTop: 90,
          gap: 48,
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
          Spam is whack-a-mole.
        </div>

        <div
          style={{
            position: "relative",
            width: 820,
            height: 280,
          }}
        >
          {BEATS.map((beat, i) => (
            <SpamBeatRow key={i} beat={beat} frame={frame} />
          ))}
        </div>

        <div
          style={{
            opacity: interpolate(frame, [320, 355], [0, 1], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
            }),
            fontFamily: theme.fontDisplay,
            fontWeight: 500,
            fontSize: 28,
            color: theme.textMuted,
            textAlign: "center",
            maxWidth: 760,
            lineHeight: 1.5,
          }}
        >
          Block one address, more spam appears in seconds.
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};

const SpamBeatRow: React.FC<{ beat: SpamBeat; frame: number }> = ({
  beat,
  frame,
}) => {
  if (frame < beat.enter || frame > beat.exit) return null;

  const enterT = interpolate(frame, [beat.enter, beat.enter + 8], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const blocked = frame >= beat.block;
  const exitT = interpolate(frame, [beat.exit - 12, beat.exit], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const dropX = interpolate(exitT, [0, 1], [0, 80]);
  const opacity = interpolate(enterT, [0, 1], [0, 1]) * (1 - exitT);
  const enterX = interpolate(enterT, [0, 1], [-40, 0]);

  return (
    <div
      style={{
        position: "absolute",
        top: 80,
        left: "50%",
        transform: `translate(-50%, 0) translateX(${enterX + dropX}px)`,
        opacity,
      }}
    >
      <InboxRow
        sender={beat.sender}
        subject={beat.subject}
        preview={beat.preview}
        spam
        blocked={blocked}
      />
    </div>
  );
};
