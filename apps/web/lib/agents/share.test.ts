import { describe, expect, it } from "vitest";
import { translate } from "../i18n/translate";
import { sanitiseNextPath } from "../url/next-path";
import { sendMessageHref, shareLink, sharedAgentName, shareText } from "./share";

const ja = (key: string, vars?: Record<string, string | number>) => translate("ja", key, vars);
const en = (key: string, vars?: Record<string, string | number>) => translate("en", key, vars);
const AID = "aid:ai:01ABCDEF";

describe("share", () => {
  it("builds the public page link with the aid encoded", () => {
    expect(shareLink("https://app.nexusinbox.ai", AID)).toBe(
      "https://app.nexusinbox.ai/to/aid:ai:01ABCDEF",
    );
    expect(shareLink("http://localhost:3103/", AID)).toBe("http://localhost:3103/to/aid:ai:01ABCDEF");
  });

  it("names the agent with its owner when there is one", () => {
    expect(sharedAgentName(ja, "秘書", "水本")).toBe("水本さんの秘書");
    expect(sharedAgentName(en, "Assistant", "Mizumoto")).toBe("Mizumoto's Assistant");
    expect(sharedAgentName(ja, "秘書", null)).toBe("秘書");
    expect(sharedAgentName(ja, "秘書", "  ")).toBe("秘書");
  });

  it("puts the introduction first and the link on its own line", () => {
    const link = shareLink("https://app.nexusinbox.ai", AID);
    expect(shareText(ja, { agent: "秘書", owner: "水本", link })).toBe(
      "水本さんの秘書に、NexusInbox で連絡できます。AI エージェントどうしで日程調整ができます。\n" + link,
    );
    expect(shareText(en, { agent: "Assistant", owner: null, link }).split("\n")).toEqual([
      "You can reach Assistant on NexusInbox. Our AI agents can find a time for us.",
      link,
    ]);
  });

  it("sends a visitor without a session through sign-in to the same picker", () => {
    expect(sendMessageHref(AID, true)).toBe("/compose?with=aid%3Aai%3A01ABCDEF");
    const viaLogin = sendMessageHref(AID, false);
    expect(viaLogin).toBe("/login?next=%2Fcompose%3Fwith%3Daid%253Aai%253A01ABCDEF");
    const next = new URL(viaLogin, "https://x.invalid").searchParams.get("next");
    expect(sanitiseNextPath(next)).toBe("/compose?with=aid%3Aai%3A01ABCDEF");
  });
});
