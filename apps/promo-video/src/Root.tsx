import React from "react";
import { Composition } from "remotion";
import { ConceptVideo, TOTAL_FRAMES } from "./ConceptVideo";

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="ConceptVideo"
        component={ConceptVideo}
        durationInFrames={TOTAL_FRAMES}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
