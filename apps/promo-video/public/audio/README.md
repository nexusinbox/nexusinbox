# Audio assets

`bgm.mp3` is a **placeholder** silent track wired into `ConceptVideo` via
Remotion's `<Audio>` component. Replace it with the real BGM when ready.

## Replacing the BGM

1. Drop the new track in this folder, named `bgm.mp3` (overwrite).
2. The track must be at least as long as the composition (~67s today).
   Longer is fine — Remotion stops it at the composition end.
3. Fade-in/out is handled in `src/ConceptVideo.tsx` via the
   `volume={(frame) => ...}` callback. Adjust there if the track has its
   own fades baked in.

## Sourcing licensed BGM

- [Pixabay Music](https://pixabay.com/music/) — CC0, no attribution required
- [freesound.org](https://freesound.org) — CC0 / CC-BY tracks
- [Suno](https://suno.com) / [ElevenLabs Sound Effects](https://elevenlabs.io)
  — generated music (verify license before commercial use)

Recommended vibe: ambient electronic / synth pad / minimal techno around
~95-110 BPM. Avoid vocals (compete with the typography) and avoid sharp
attack (clashes with scene transitions).
