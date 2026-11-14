"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ReactNode, Suspense, useEffect, useState } from "react";
import {
  useAgentDraftsQuery,
  useAgentsQuery,
  useAuthSessionQuery,
  useMessagesQuery,
} from "../../lib/api/hooks";
import { useTranslation } from "../../lib/i18n";
import { AuthLogoutButton } from "./AuthLogoutButton";
import { AuthSessionStatus } from "./AuthSessionStatus";
import { DisplayNamePrompt } from "./DisplayNamePrompt";
import { NewVersionNotice } from "./NewVersionNotice";
import { ThemeSwitcher } from "./ThemeSwitcher";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { Logo } from "./Logo";
import { RealtimeSubscriber } from "./RealtimeSubscriber";

type AppShellProps = {
  /** Page name: the heading at the top of the column and the tab title. */
  title: string;
  activePath: string;
  rightAction?: ReactNode;
  searchValue?: string;
  searchPlaceholder?: string;
  onSearchChange?: (value: string) => void;
  onSearchSubmit?: () => void;
  children: ReactNode;
};

type NavItem = {
  href: string;
  labelKey: string;
  /** Shorter label for the phone tab bar. */
  tabKey?: string;
  countKey: "inboxUnread" | "pending" | null;
  icon: ReactNode;
};

const ICON = { width: 24, height: 24, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round" } as const;

const messagesItem: NavItem = {
  href: "/",
  labelKey: "nav.inbox",
  tabKey: "nav.tabInbox",
  countKey: "inboxUnread",
  icon: (
    <svg {...ICON}>
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
      <polyline points="22,6 12,13 2,6" />
    </svg>
  ),
};
const pendingItem: NavItem = {
  href: "/pending",
  labelKey: "nav.pending",
  tabKey: "nav.tabPending",
  countKey: "pending",
  icon: (
    <svg {...ICON}>
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  ),
};
const agentsItem: NavItem = {
  href: "/settings/agents",
  labelKey: "nav.agentSettings",
  tabKey: "nav.agentSettings",
  countKey: null,
  icon: (
    <svg {...ICON}>
      <rect x="4" y="7" width="16" height="12" rx="3" />
      <path d="M12 3v4" />
      <circle cx="9" cy="13" r="1.2" />
      <circle cx="15" cy="13" r="1.2" />
    </svg>
  ),
};
const contactsItem: NavItem = {
  href: "/contacts",
  labelKey: "nav.contacts",
  tabKey: "nav.contacts",
  countKey: null,
  icon: (
    <svg {...ICON}>
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  ),
};

/** The left navigation (and the phone drawer), in order. */
const navItems: NavItem[] = [
  messagesItem,
  pendingItem,
  {
    href: "/?view=archive",
    labelKey: "nav.archive",
    countKey: null,
    icon: (
      <svg {...ICON}>
        <polyline points="21 8 21 21 3 21 3 8" />
        <rect x="1" y="3" width="22" height="5" />
        <line x1="10" y1="12" x2="14" y2="12" />
      </svg>
    ),
  },
  agentsItem,
  contactsItem,
  {
    href: "/settings/audit",
    labelKey: "nav.auditLog",
    countKey: null,
    icon: (
      <svg {...ICON}>
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
      </svg>
    ),
  },
  {
    href: "/help",
    labelKey: "topbar.help",
    countKey: null,
    icon: (
      <svg {...ICON}>
        <circle cx="12" cy="12" r="10" />
        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    ),
  },
];

/** The phone tab bar: the four places people go most. */
const tabItems: NavItem[] = [messagesItem, pendingItem, agentsItem, contactsItem];

function avatarInitial(source: string | null | undefined, fallback: string): string {
  if (!source) return fallback;
  const trimmed = source.trim();
  if (!trimmed) return fallback;
  return trimmed.charAt(0).toUpperCase();
}

export function AppShell({
  title,
  activePath,
  rightAction,
  searchValue,
  searchPlaceholder,
  onSearchChange,
  onSearchSubmit,
  children,
}: AppShellProps) {
  const { t } = useTranslation();

  // The browser tab title follows the page name. Next applies the root
  // layout's title again after client navigations (even a search-param
  // change), so put ours back whenever <head> changes.
  useEffect(() => {
    if (typeof document === "undefined") return;
    const base = "NexusInbox";
    const wanted = title ? `${title} · ${base}` : base;
    const apply = () => {
      if (document.title !== wanted) document.title = wanted;
    };
    apply();
    const observer = new MutationObserver(apply);
    observer.observe(document.head, { childList: true, subtree: true, characterData: true });
    return () => observer.disconnect();
  }, [title]);

  const sessionQuery = useAuthSessionQuery();
  const unreadQuery = useMessagesQuery({
    agentDid: "all",
    status: "unread",
    folder: "inbox",
    page: 1,
    perPage: 1,
  });
  const pendingQuery = useMessagesQuery({
    agentDid: "all",
    folder: "pending_approval",
    page: 1,
    perPage: 1,
  });

  const inboxUnread = unreadQuery.data?.total ?? null;
  // 「新しい会話」 needs an agent to send from: shown once there is one.
  const agentsQuery = useAgentsQuery();
  const canCompose = (agentsQuery.data?.agents.length ?? 0) > 0;
  // 確認が必要 covers held messages and AI drafts (docs/33 §9).
  const draftsQuery = useAgentDraftsQuery();
  const pendingCount =
    pendingQuery.data || draftsQuery.data
      ? (pendingQuery.data?.total ?? 0) + (draftsQuery.data?.drafts?.length ?? 0)
      : null;

  const counts: Record<"inboxUnread" | "pending", number | null> = {
    inboxUnread,
    pending: pendingCount,
  };

  const user = sessionQuery.data?.user;
  const avatarLabel = avatarInitial(user?.display_name ?? user?.id, "?");
  const avatarTooltip = user?.display_name ?? user?.id ?? t("topbar.profile");

  // Pick the longest href that matches activePath so nested routes (e.g.
  // /settings/agents/new) highlight only the most specific entry.
  const activeHref = navItems
    .map((item) => item.href)
    .filter((href) => activePath === href || activePath.startsWith(href + "/"))
    .sort((a, b) => b.length - a.length)[0];

  // Mobile drawer state. The drawer is hidden by default; the
  // hamburger button in the topbar opens it, the backdrop click /
  // navigation / Esc closes it. Closed automatically when the route
  // changes so a sidebar nav-tap doesn't leave the drawer open over
  // the new screen.
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const pathname = usePathname();
  useEffect(() => {
    setMobileNavOpen(false);
  }, [pathname]);
  // Lock body scroll while the drawer is open so the page behind it
  // doesn't jiggle when the user scrolls inside the drawer itself.
  useEffect(() => {
    if (typeof document === "undefined") return;
    const previous = document.body.style.overflow;
    if (mobileNavOpen) document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
    };
  }, [mobileNavOpen]);
  // Esc closes the drawer.
  useEffect(() => {
    if (!mobileNavOpen) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavOpen(false);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [mobileNavOpen]);

  const countFor = (item: NavItem) => {
    const n = item.countKey ? counts[item.countKey] : null;
    return n !== null && n > 0 ? n : null;
  };

  const search = onSearchChange ? (
    <div className="x-search">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
      <input
        aria-label={t("topbar.searchLabel")}
        placeholder={searchPlaceholder ?? t("topbar.searchPlaceholder")}
        value={searchValue}
        onChange={(event) => onSearchChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") onSearchSubmit?.();
        }}
      />
    </div>
  ) : null;

  return (
    <div className="x-shell" data-mobile-nav={mobileNavOpen ? "open" : "closed"}>
      <DisplayNamePrompt />
      <NewVersionNotice />
      {mobileNavOpen ? (
        <button
          type="button"
          className="x-drawer-backdrop"
          aria-label={t("nav.closeMenu")}
          onClick={() => setMobileNavOpen(false)}
        />
      ) : null}

      {/* Left navigation on wide screens; a slide-in drawer on phones. */}
      <aside className="x-nav" id="x-nav-drawer">
        <Link href="/" className="x-brand" aria-label={t("nav.inbox")}>
          <Logo size={32} variant="light" />
          <span>
            Nexus<b>Inbox</b>
          </span>
        </Link>
        <nav className="x-nav-list">
          {navItems.map((item) => {
            const count = countFor(item);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={"x-nav-item" + (item.href === activeHref ? " active" : "")}
                aria-current={item.href === activeHref ? "page" : undefined}
              >
                {item.icon}
                <span className="x-nav-label">{t(item.labelKey)}</span>
                {count !== null ? (
                  <span className="x-count" data-testid={`mailbox-count-${item.countKey}`}>
                    {count}
                  </span>
                ) : null}
              </Link>
            );
          })}
        </nav>
        {canCompose ? (
          <Link href="/compose" className="x-compose">
            {t("nav.newConversation")}
          </Link>
        ) : null}
        <div className="x-me">
          <Link
            className="x-avatar"
            href="/settings/profile"
            aria-label={t("topbar.profile")}
            title={avatarTooltip}
            data-testid="topbar-avatar"
          >
            {avatarLabel}
          </Link>
          <div className="x-me-name">
            <b>{user?.display_name ?? t("topbar.profile")}</b>
          </div>
          <Link className="icon-btn" href="/integrations" aria-label={t("topbar.apps")} title={t("topbar.apps")}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <circle cx="6" cy="6" r="2" />
              <circle cx="12" cy="6" r="2" />
              <circle cx="18" cy="6" r="2" />
              <circle cx="6" cy="12" r="2" />
              <circle cx="12" cy="12" r="2" />
              <circle cx="18" cy="12" r="2" />
              <circle cx="6" cy="18" r="2" />
              <circle cx="12" cy="18" r="2" />
              <circle cx="18" cy="18" r="2" />
            </svg>
          </Link>
          <LanguageSwitcher />
          <AuthLogoutButton />
        </div>
        <ThemeSwitcher />
      </aside>

      <section className="x-main">
        <header className="x-head">
          {/* Phones: the avatar opens the drawer (as on X). */}
          <button
            type="button"
            className="x-drawer-toggle x-avatar"
            aria-label={t("nav.openMenu")}
            aria-expanded={mobileNavOpen}
            aria-controls="x-nav-drawer"
            onClick={() => setMobileNavOpen((v) => !v)}
          >
            {avatarLabel}
          </button>
          <h1 className="x-title">{title}</h1>
          {search}
          {rightAction ? <div className="x-head-action">{rightAction}</div> : null}
          <Suspense fallback={null}>
            <AuthSessionStatus />
          </Suspense>
          <Suspense fallback={null}>
            <RealtimeSubscriber />
          </Suspense>
        </header>
        <main className="page-content">{children}</main>
      </section>

      {/* Phones: the four main places, and a button for a new conversation. */}
      <nav className="x-tabbar" aria-label={t("nav.tabs")}>
        {tabItems.map((item) => {
          const count = countFor(item);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={"x-tab" + (item.href === activeHref ? " active" : "")}
              aria-current={item.href === activeHref ? "page" : undefined}
            >
              {item.icon}
              <span>{t(item.tabKey ?? item.labelKey)}</span>
              {count !== null ? <span className="x-count">{count}</span> : null}
            </Link>
          );
        })}
      </nav>
      {/* Not on the compose page itself: it would cover what is being written. */}
      {canCompose && !activePath.startsWith("/compose") ? (
        <Link href="/compose" className="x-fab" aria-label={t("nav.newConversation")}>
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" aria-hidden="true">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
        </Link>
      ) : null}
    </div>
  );
}
