"use client";

import {
  CSSProperties,
  MouseEvent as ReactMouseEvent,
  useCallback,
  useEffect,
  useState,
} from "react";

// Shared 2-column resize hook used by pages that embed a `mail-layout`
// shell with a list column + a reader column (pending / settings/agents
// / settings/blocks). The 3-column dashboard / agent inbox manage their
// own state because they also need a second resizer for the side panel.

export type TwoColumnResize = {
  threadWidth: number;
  layoutStyle: CSSProperties;
  startResize: (event: ReactMouseEvent) => void;
};

type Options = {
  storageKey: string;
  initialWidth?: number;
  min?: number;
  max?: number;
  readerMinWidth?: number;
};

export function useTwoColumnResize(options: Options): TwoColumnResize {
  const {
    storageKey,
    initialWidth = 360,
    min = 220,
    max = 800,
    readerMinWidth = 540,
  } = options;

  const [threadWidth, setThreadWidth] = useState<number>(initialWidth);

  // Hydrate persisted width on mount.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) return;
    const parsed = Number.parseInt(raw, 10);
    if (Number.isFinite(parsed)) {
      setThreadWidth(Math.max(min, Math.min(max, parsed)));
    }
  }, [storageKey, min, max]);

  // Persist on every change.
  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(storageKey, String(threadWidth));
  }, [storageKey, threadWidth]);

  const startResize = useCallback(
    (event: ReactMouseEvent) => {
      event.preventDefault();
      const startX = event.clientX;
      const startWidth = threadWidth;
      const onMouseMove = (moveEvent: MouseEvent) => {
        const next = startWidth + (moveEvent.clientX - startX);
        setThreadWidth(Math.max(min, Math.min(max, next)));
      };
      const onMouseUp = () => {
        window.removeEventListener("mousemove", onMouseMove);
        window.removeEventListener("mouseup", onMouseUp);
        document.body.style.cursor = "";
      };
      window.addEventListener("mousemove", onMouseMove);
      window.addEventListener("mouseup", onMouseUp);
      document.body.style.cursor = "col-resize";
    },
    [threadWidth, min, max],
  );

  const layoutStyle: CSSProperties = {
    gridTemplateColumns: `${threadWidth}px 4px minmax(${readerMinWidth}px, 1fr)`,
  };

  return { threadWidth, layoutStyle, startResize };
}
