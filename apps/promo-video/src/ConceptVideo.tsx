import React from "react";
import { AbsoluteFill, Audio, Sequence, staticFile } from "remotion";
import { Scene1Brand } from "./scenes/Scene1Brand";
import { Scene2Whackamole } from "./scenes/Scene2Whackamole";
import { Scene3AIScale } from "./scenes/Scene3AIScale";
import { Scene4HumanBlock } from "./scenes/Scene4HumanBlock";
import { Scene5AgentsCollaborate } from "./scenes/Scene5AgentsCollaborate";
import { Scene6CTA } from "./scenes/Scene6CTA";

// Scene timings (frames at 30fps)
export const SCENE_FRAMES = {
  scene1: 180, // 0:00–0:06   Brand + slogan
  scene2: 360, // 0:06–0:18   Whack-a-mole problem
  scene3: 300, // 0:18–0:28   AI scales the problem
  scene4: 540, // 0:28–0:46   Human-level block (the solution)
  scene5: 360, // 0:46–0:58   Agents collaborate autonomously
  scene6: 270, // 0:58–1:07   Brand + CTA
} as const;

const S = SCENE_FRAMES;
const OFFSETS = {
  scene1: 0,
  scene2: S.scene1,
  scene3: S.scene1 + S.scene2,
  scene4: S.scene1 + S.scene2 + S.scene3,
  scene5: S.scene1 + S.scene2 + S.scene3 + S.scene4,
  scene6: S.scene1 + S.scene2 + S.scene3 + S.scene4 + S.scene5,
} as const;

export const TOTAL_FRAMES =
  S.scene1 + S.scene2 + S.scene3 + S.scene4 + S.scene5 + S.scene6;

const FADE_IN_FRAMES = 30;
const FADE_OUT_FRAMES = 45;
const BASE_VOLUME = 0.45;

const bgmVolume = (frame: number) => {
  const fadeIn = Math.min(1, Math.max(0, frame / FADE_IN_FRAMES));
  const fadeOut = Math.min(
    1,
    Math.max(0, (TOTAL_FRAMES - frame) / FADE_OUT_FRAMES),
  );
  return Math.min(fadeIn, fadeOut) * BASE_VOLUME;
};

export const ConceptVideo: React.FC = () => {
  return (
    <AbsoluteFill style={{ background: "#0a0c18" }}>
      {/* BGM track. Replace public/audio/bgm.mp3 with the real track —
          see public/audio/README.md for guidance. */}
      <Audio src={staticFile("audio/bgm.mp3")} volume={bgmVolume} />

      <Sequence from={OFFSETS.scene1} durationInFrames={S.scene1}>
        <Scene1Brand />
      </Sequence>
      <Sequence from={OFFSETS.scene2} durationInFrames={S.scene2}>
        <Scene2Whackamole />
      </Sequence>
      <Sequence from={OFFSETS.scene3} durationInFrames={S.scene3}>
        <Scene3AIScale />
      </Sequence>
      <Sequence from={OFFSETS.scene4} durationInFrames={S.scene4}>
        <Scene4HumanBlock />
      </Sequence>
      <Sequence from={OFFSETS.scene5} durationInFrames={S.scene5}>
        <Scene5AgentsCollaborate />
      </Sequence>
      <Sequence from={OFFSETS.scene6} durationInFrames={S.scene6}>
        <Scene6CTA />
      </Sequence>
    </AbsoluteFill>
  );
};
