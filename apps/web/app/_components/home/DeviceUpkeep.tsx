"use client";

// What the inbox notices did on their own (settle computers connected with
// a code made here, approve a lone browser, remember devices seen the first
// time), on the screens people open every day: Home and the conversations.

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { queryKeys } from "../../../lib/api/hooks";
import type { Agent } from "../../../lib/api/types";
import { keepDevicesUpToDate } from "../../../lib/home/device-attention";
import { attentionDevicesKey } from "../../../lib/home/use-attention";

export function DeviceUpkeep({ agents }: { agents: Agent[] }) {
  const queryClient = useQueryClient();
  // Once per state of the agents' devices and lists, so a failed write is
  // not retried in a loop.
  const done = useRef(new Set<string>());
  const key = agents
    .map((a) => `${a.aid}:${a.device_list?.jws ?? ""}:${(a.devices ?? []).map((d) => `${d.did}=${d.encryption_public_key ?? ""}`).join(",")}`)
    .join("|");
  useEffect(() => {
    if (agents.length === 0 || done.current.has(key)) return;
    done.current.add(key);
    void keepDevicesUpToDate(agents).then((changed) => {
      if (changed) void queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
      void queryClient.invalidateQueries({ queryKey: attentionDevicesKey });
    });
    // `key` stands for `agents`.
  }, [key]);
  return null;
}
