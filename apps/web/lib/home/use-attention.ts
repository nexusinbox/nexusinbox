"use client";

// Home's 「あなたの判断が必要」 and the count beside ホーム in the navigation
// (docs/41 §6). Loading, failed and zero stay apart: while any source is
// loading or failed, there is no count.

import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState } from "react";
import { defaultApiClient } from "../api/client";
import { queryKeys, useAgentDraftsQuery, useAgentsQuery } from "../api/hooks";
import { arrangeAttention, withUnloaded, type Arranged, type AttentionItem } from "./attention";
import { collectDeviceAttention, stoppedAttention } from "./device-attention";
import { isPutOff, putOff } from "./put-off";

export const attentionDevicesKey = ["attention", "devices"] as const;

/** Held messages are read a page at a time; the rest on request. */
const HELD_PAGE = 100;

export type Attention =
  | { state: "loading" }
  | { state: "error"; retry: () => void }
  | ({
      state: "ready";
      putOff: (item: AttentionItem) => void;
      refresh: () => void;
      /** Held messages the server counts but this page has not read yet. */
      heldUnloaded: number;
      loadMoreHeld: () => void;
      loadingMoreHeld: boolean;
    } & Arranged);

export function useAttention(): Attention {
  const queryClient = useQueryClient();
  const agentsQuery = useAgentsQuery();
  const draftsQuery = useAgentDraftsQuery();
  // Under the "messages" key, so what changes a message refreshes it too.
  const heldQuery = useInfiniteQuery({
    queryKey: [...queryKeys.messages({ agentDid: "all", folder: "pending_approval", perPage: HELD_PAGE }), "pages"],
    queryFn: ({ pageParam }) =>
      defaultApiClient.listMessages({ agentDid: "all", folder: "pending_approval", page: pageParam, perPage: HELD_PAGE }),
    initialPageParam: 1,
    getNextPageParam: (last, pages) => {
      const read = pages.reduce((n, p) => n + p.messages.length, 0);
      return last.messages.length > 0 && read < last.total ? pages.length + 1 : undefined;
    },
    staleTime: 30_000,
    retry: 1,
  });
  const heldPages = heldQuery.data?.pages ?? [];
  const held = heldPages.flatMap((p) => p.messages);
  const heldTotal = heldPages.length > 0 ? heldPages[heldPages.length - 1].total : 0;
  const heldUnloaded = Math.max(0, heldTotal - held.length);
  const agents = useMemo(() => agentsQuery.data?.agents ?? [], [agentsQuery.data]);
  // Anything a device check depends on: a change means a new check.
  const agentsKey = agents
    .map((a) => `${a.aid}:${a.device_list?.jws ?? ""}:${(a.devices ?? []).map((d) => `${d.did}=${d.encryption_public_key ?? ""}`).join(",")}`)
    .join("|");
  // A computer counts as stopped after a while: look again every minute.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(id);
  }, []);
  const devicesQuery = useQuery({
    queryKey: [...attentionDevicesKey, agentsKey],
    queryFn: () => collectDeviceAttention(agents),
    enabled: agentsQuery.isSuccess,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1,
  });
  // 「あとで」 lives in this browser; bump to arrange again.
  const [, setVersion] = useState(0);

  const refresh = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: attentionDevicesKey });
    setVersion((v) => v + 1);
  }, [queryClient]);

  const sources = [agentsQuery, draftsQuery, heldQuery, devicesQuery] as const;
  const failed = sources.some((q) => q.isError);
  const ready = agentsQuery.data && draftsQuery.data && heldQuery.data && devicesQuery.data;

  // Cheap enough to arrange on every render, which also re-reads what was
  // put off (`version` re-renders after 「あとで」).
  const arranged: Arranged | null = ready
    ? arrangeAttention(
        [
          ...(devicesQuery.data ?? []),
          ...(draftsQuery.data?.drafts ?? []).map((draft) => ({ kind: "draft" as const, draft })),
          ...held.map((message) => ({ kind: "held" as const, message })),
          ...stoppedAttention(agents, now),
        ],
        isPutOff,
      )
    : null;

  if (failed) {
    return {
      state: "error",
      retry: () => {
        for (const q of sources) if (q.isError) void q.refetch();
      },
    };
  }
  if (!arranged) return { state: "loading" };
  return {
    state: "ready",
    ...withUnloaded(arranged, heldUnloaded),
    heldUnloaded,
    loadMoreHeld: () => void heldQuery.fetchNextPage(),
    loadingMoreHeld: heldQuery.isFetchingNextPage,
    refresh,
    putOff: (item) => {
      putOff(item);
      setVersion((v) => v + 1);
    },
  };
}
