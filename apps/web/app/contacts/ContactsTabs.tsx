"use client";

// コンタクト / ブロック中: the two lists people manage about others. Blocked
// senders live under Contacts so they can be found (and unblocked) without
// a separate menu entry.

import Link from "next/link";
import { useBlocksQuery } from "../../lib/api/hooks";
import { useTranslation } from "../../lib/i18n";

export function ContactsTabs({ active }: { active: "contacts" | "blocks" }) {
  const { t } = useTranslation();
  const blocksQuery = useBlocksQuery();
  const blocked = blocksQuery.data?.blocks.length ?? 0;
  return (
    <nav className="ct-tabs" aria-label={t("contacts.tabsLabel")}>
      <Link
        href="/contacts"
        className={active === "contacts" ? "on" : ""}
        aria-current={active === "contacts" ? "page" : undefined}
      >
        {t("contacts.tabContacts")}
      </Link>
      <Link
        href="/settings/blocks"
        className={active === "blocks" ? "on" : ""}
        aria-current={active === "blocks" ? "page" : undefined}
        data-testid="contacts-tab-blocks"
      >
        {t("contacts.tabBlocks")}
        {blocked > 0 ? <span className="ct-tab-count">{blocked}</span> : null}
      </Link>
    </nav>
  );
}
