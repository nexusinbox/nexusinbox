"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { useAuthSessionQuery } from "../../lib/api/hooks";

type ConnectionState = "idle" | "connecting" | "open" | "retrying" | "closed";

type WsEvent = {
  event?: string;
  data?: {
    message_id?: string;
    agent_did?: string;
    sender_did?: string;
    subject_encrypted?: string;
    priority?: string;
    timestamp?: string;
  };
};

/**
 * Build the WebSocket URL. Same-origin `/api/ws` is rewritten by Next.js to the
 * Rust API, which supports cookie auth so the upgrade carries the session.
 * NEXT_PUBLIC_WS_URL overrides for Tauri/desktop builds that talk to the API
 * directly. This is also used in the CSP connect-src directive (next.config.ts).
 */
function buildWsUrl(): string | null {
  if (typeof window === "undefined") return null;
  const override = process.env.NEXT_PUBLIC_WS_URL;
  if (override && override.trim().length > 0) return override.trim();
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${window.location.host}/api/ws`;
}

const MAX_BACKOFF_MS = 30_000;
const BASE_BACKOFF_MS = 1_000;

export function RealtimeSubscriber() {
  const queryClient = useQueryClient();
  // Use the shared session hook so every consumer (AppShell,
  // AuthSessionStatus, Realtime) reads from one query observer.
  const sessionQuery = useAuthSessionQuery();
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [connectionState, setConnectionState] = useState<ConnectionState>("idle");
  const socketRef = useRef<WebSocket | null>(null);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryAttemptRef = useRef(0);
  const cancelledRef = useRef(false);

  useEffect(() => {
    if (!sessionQuery.data?.authenticated) {
      return;
    }
    cancelledRef.current = false;

    const connect = () => {
      const url = buildWsUrl();
      if (!url) return;
      setConnectionState(retryAttemptRef.current === 0 ? "connecting" : "retrying");

      let socket: WebSocket;
      try {
        socket = new WebSocket(url);
      } catch {
        scheduleReconnect();
        return;
      }
      socketRef.current = socket;

      socket.onopen = () => {
        retryAttemptRef.current = 0;
        setConnectionState("open");
      };

      socket.onmessage = (event) => {
        let parsed: WsEvent | null = null;
        try {
          parsed = typeof event.data === "string" ? (JSON.parse(event.data) as WsEvent) : null;
        } catch {
          parsed = null;
        }
        // Any server push invalidates the messages list. Content queries are
        // fetched lazily per-message so they don't need eager invalidation.
        if (parsed && parsed.event === "new_message") {
          queryClient.invalidateQueries({ queryKey: ["messages"] });
        }
      };

      socket.onerror = () => {
        // onclose will fire right after; handle retry there to avoid double-schedule.
      };

      socket.onclose = () => {
        socketRef.current = null;
        if (cancelledRef.current) {
          setConnectionState("closed");
          return;
        }
        scheduleReconnect();
      };
    };

    const scheduleReconnect = () => {
      if (cancelledRef.current) return;
      const attempt = retryAttemptRef.current;
      const delay = Math.min(BASE_BACKOFF_MS * 2 ** attempt, MAX_BACKOFF_MS);
      retryAttemptRef.current = attempt + 1;
      setConnectionState("retrying");
      retryTimerRef.current = setTimeout(connect, delay);
    };

    connect();

    return () => {
      cancelledRef.current = true;
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
      if (socketRef.current) {
        try {
          socketRef.current.close();
        } catch {
          // ignore
        }
        socketRef.current = null;
      }
      retryAttemptRef.current = 0;
      setConnectionState("idle");
    };
  }, [queryClient, sessionQuery.data?.authenticated]);

  if (!sessionQuery.data?.authenticated) {
    return null;
  }

  // WebSocket connection is managed in the background.
  // No visible UI — the connection status is an implementation detail.
  return null;
}
