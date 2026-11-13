// The Standard mode runtime checks recipients like the gateway (docs/40
// §13.2): only listed devices, and a stop when the root changes.

import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RecipientResolution } from "@nexusinbox/core";
import { checkRecipient, SendStoppedError } from "../src/device-trust.js";

const vectors = JSON.parse(
  readFileSync(path.join(__dirname, "../../../tests/vectors/device_list_decisions.json"), "utf8"),
) as { cases: { served: RecipientResolution }[] };
const served = (i: number) => vectors.cases[i].served;

let dir: string;
let file: string;
beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "peers-"));
  file = path.join(dir, "c1.peers.json");
});
afterEach(() => rm(dir, { recursive: true, force: true }));

describe("checkRecipient (docs/40 §13.2)", () => {
  it("returns only listed devices, remembers the root, and stops when it changes", async () => {
    const added = served(1);
    const checked = await checkRecipient(added, added.aid, file);
    expect(checked.devices?.map((d) => d.did).sort()).toEqual(served(0).devices!.map((d) => d.did).sort());
    expect(checked.did).not.toBe(added.did);
    expect(((await stat(file)).mode & 0o777).toString(8)).toBe("600");

    const swapped = served(10);
    const stop = await checkRecipient(swapped, swapped.aid, file).catch((e) => e);
    expect(stop).toBeInstanceOf(SendStoppedError);
    expect(stop).toMatchObject({ reason: "root_changed" });
    const peers = JSON.parse(await readFile(file, "utf8"));
    expect(peers.changed[swapped.aid]).toBe(stop.root);
  });
});
