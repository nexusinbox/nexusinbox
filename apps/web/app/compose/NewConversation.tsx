"use client";

// 新しい会話 (docs/35 §2): choose the sending agent, then the recipient from
// contacts and own agents, or a pasted address. Picking one opens the
// conversation on the messages screen with the composer ready.

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { AppShell } from "../_components/AppShell";
import { Avatar } from "../_components/messages/ConversationView";
import { useAgentsQuery, useContactsQuery } from "../../lib/api/hooks";
import { formatPartyLabel } from "../../lib/api/labels";
import { buildRecipientOptions, type RecipientOption } from "../../lib/contacts/recipient-options";
import { hasSigningPrivateKeyMaterial } from "../../lib/crypto/signing-keyring";
import { useTranslation } from "../../lib/i18n";

/** Looks like an address someone pasted (not a name to search for). */
function isAddress(value: string): boolean {
  return value.startsWith("aid:ai:") || value.startsWith("did:key:");
}

export function NewConversation() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();
  const agentsQuery = useAgentsQuery();
  const contactsQuery = useContactsQuery();
  const agents = useMemo(() => agentsQuery.data?.agents ?? [], [agentsQuery.data]);
  const contacts = useMemo(() => contactsQuery.data?.contacts ?? [], [contactsQuery.data]);

  // Only agents whose signing key is in this browser can send from here
  // (the same check as the conversation's composer).
  const [sendable, setSendable] = useState<Set<string> | null>(null);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const found = new Set<string>();
      for (const agent of agents) {
        for (const did of Array.from(new Set([agent.did, ...(agent.dids ?? [])]))) {
          if (await hasSigningPrivateKeyMaterial(did)) {
            found.add(agent.did);
            break;
          }
        }
      }
      if (!cancelled) setSendable(found);
    })();
    return () => {
      cancelled = true;
    };
  }, [agents]);

  const senders = useMemo(
    () => agents.filter((a) => sendable?.has(a.did)),
    [agents, sendable],
  );
  const [senderDid, setSenderDid] = useState("");
  const sender = senders.find((a) => a.did === senderDid) ?? senders[0];

  // ?with=<address> (from コンタクト): start with that recipient filtered.
  const [query, setQuery] = useState(() => searchParams?.get("with")?.trim() ?? "");
  const typed = query.trim();
  const options = useMemo(() => buildRecipientOptions(agents, contacts), [agents, contacts]);
  const matches = useMemo(() => {
    const needle = typed.toLowerCase();
    return options.filter(
      (o) =>
        !needle ||
        o.label.toLowerCase().includes(needle) ||
        formatPartyLabel(o.label, t).toLowerCase().includes(needle) ||
        o.address.toLowerCase().includes(needle),
    );
  }, [options, typed, t]);
  const pasted = isAddress(typed) && !options.some((o) => o.address === typed) ? typed : "";

  const open = (address: string) => {
    if (!sender) return;
    router.push(`/?with=${encodeURIComponent(address)}&as=${encodeURIComponent(sender.did)}`);
  };

  const fullFormHref =
    "/compose?full=1" +
    (sender ? `&as=${encodeURIComponent(sender.did)}` : "") +
    (isAddress(typed) ? `&to=${encodeURIComponent(typed)}` : "");

  const row = (o: RecipientOption) => {
    const name = formatPartyLabel(o.label, t);
    return (
      <button
        type="button"
        key={o.kind + "-" + o.address}
        className="dm-row"
        onClick={() => open(o.address)}
        disabled={!sender}
        data-testid="new-conversation-recipient"
      >
        <Avatar did={o.did} name={name} />
        <span className="dm-row-body">
          <span className="dm-line1">
            <span className="dm-name">{name}</span>
          </span>
          <span className="dm-preview">{o.address}</span>
        </span>
      </button>
    );
  };

  const loading = agentsQuery.isLoading || sendable === null;
  const someOnComputer = !loading && senders.length > 0 && senders.length < agents.length;

  return (
    <AppShell title={t("compose.title")} activePath="/compose">
      <div className="nc">
        <div className="nc-block">
          <div className="nc-label">{t("compose.pickFrom")}</div>
          {loading ? (
            <p className="dm-muted">{t("inbox.loading")}</p>
          ) : agents.length === 0 ? (
            <p className="dm-muted">
              {t("compose.pickNoAgent")}{" "}
              {/* Keep an address (e.g. from a shared intro page, docs/36) so
                  the first-run guide can bring them back to it. */}
              <Link
                href={isAddress(typed) ? `/onboarding?with=${encodeURIComponent(typed)}` : "/onboarding"}
                className="dm-link"
              >
                {t("agents.newAgent")}
              </Link>
            </p>
          ) : senders.length === 0 ? (
            <p className="dm-muted">{t("compose.pickNoSender")}</p>
          ) : (
            <div className="nc-chips">
              {senders.map((a) => (
                <button
                  key={a.did}
                  type="button"
                  className={"dm-chip" + (a.did === sender?.did ? " on" : "")}
                  aria-pressed={a.did === sender?.did}
                  onClick={() => setSenderDid(a.did)}
                >
                  {a.label}
                </button>
              ))}
            </div>
          )}
          {someOnComputer ? <p className="nc-note">{t("compose.pickSomeOnComputer")}</p> : null}
        </div>

        <label className="nc-block nc-search">
          <span className="nc-label">{t("compose.toLabel")}</span>
          <input
            className="nc-input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("compose.toPlaceholder")}
            autoComplete="off"
            data-testid="new-conversation-search"
          />
        </label>

        {pasted ? (
          <>
            <div className="nc-group">{t("compose.pickAddress")}</div>
            <button
              type="button"
              className="dm-row"
              onClick={() => open(pasted)}
              disabled={!sender}
              data-testid="new-conversation-address"
            >
              <Avatar did={pasted} name="@" />
              <span className="dm-row-body">
                <span className="dm-line1">
                  <span className="dm-name">{t("compose.pickSendToAddress")}</span>
                </span>
                <span className="dm-preview">{pasted}</span>
              </span>
            </button>
          </>
        ) : null}

        {(["contact", "own"] as const).map((kind) => {
          const group = matches.filter((o) => o.kind === kind);
          if (group.length === 0) return null;
          return (
            <div key={kind}>
              <div className="nc-group">
                {kind === "contact" ? t("compose.toGroupContacts") : t("compose.toGroupOwn")}
              </div>
              {group.map(row)}
            </div>
          );
        })}

        {!pasted && matches.length === 0 && !agentsQuery.isLoading ? (
          <p className="dm-empty">{typed ? t("compose.pickNoMatch") : t("compose.pickNobody")}</p>
        ) : null}

        <div className="nc-foot">
          <Link href={fullFormHref} className="dm-link" data-testid="new-conversation-full-form">
            {t("messages.composeMore")}
          </Link>
          <Link href="/compose/propose" className="dm-link">
            {t("a2a.proposeComposeLink")}
          </Link>
        </div>
      </div>
    </AppShell>
  );
}
