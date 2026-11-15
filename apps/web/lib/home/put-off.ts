// 「あとで」 on Home (docs/41 §6.1.1), kept in this browser only. The keys
// are the ones the inbox notices used, so what was put off there stays put
// off. A stopped computer is put off for that stop: if it stops again, it
// is a new problem and shows again.

import type { AttentionItem } from "./attention";

const undecidedKey = (aid: string) => `nexusinbox.devicelist.later.${aid}`;
const stoppedKey = (did: string) => `nexusinbox.stopped.dismissed.${did}`;

function read(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    // Storage blocked: nothing is put off.
    return null;
  }
}

export function isPutOff(item: AttentionItem): boolean {
  if (item.kind === "list_undecided") return read(undecidedKey(item.agent.aid)) !== null;
  if (item.kind === "computer_stopped") return read(stoppedKey(item.device.did)) === String(item.since);
  return false;
}

export function putOff(item: AttentionItem): void {
  try {
    if (item.kind === "list_undecided") window.localStorage.setItem(undecidedKey(item.agent.aid), "1");
    else if (item.kind === "computer_stopped") window.localStorage.setItem(stoppedKey(item.device.did), String(item.since));
  } catch {
    // ignore
  }
}
