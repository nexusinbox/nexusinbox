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
import { AppBackdrop } from "./AppBackdrop";
import { AuthLogoutButton } from "./AuthLogoutButton";
import { AuthSessionStatus } from "./AuthSessionStatus";
import { DisplayNamePrompt } from "./DisplayNamePrompt";
import { NewVersionNotice } from "./NewVersionNotice";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { Logo } from "./Logo";
import { RealtimeSubscriber } from "./RealtimeSubscriber";

type AppShellProps = {
  /**
   * Page label. Sets the browser-tab title via the effect below; the
   * value is NOT rendered on-page — Gmail-style chrome intentionally
   * drops the heading since the sidebar highlight already signals
   * "which section are we in". If a page needs explanatory copy, put
   * it inside the main content column, not at the viewport top.
   */
  title: string;
  activePath: string;
  rightAction?: ReactNode;
  searchValue?: string;
  searchPlaceholder?: string;
  onSearchChange?: (value: string) => void;
  onSearchSubmit?: () => void;
  children: ReactNode;
};

type MailboxItem = {
  href: string;
  labelKey: string;
  countKey: "inboxUnread" | "agents" | "pending" | null;
  icon: ReactNode;
};

type MailboxSection = {
  id: string;
  titleKey: string;
  items: MailboxItem[];
};

const mailItems: MailboxItem[] = [
  {
    href: "/",
    labelKey: "nav.inbox",
    countKey: "inboxUnread",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
        <polyline points="22,6 12,13 2,6" />
      </svg>
    )
  },
  {
    href: "/pending",
    labelKey: "nav.pending",
    countKey: "pending",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <polyline points="12 6 12 12 16 14" />
      </svg>
    ),
  },
  {
    href: "/?view=sent",
    labelKey: "nav.sent",
    countKey: null,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <line x1="22" y1="2" x2="11" y2="13" />
        <polygon points="22 2 15 22 11 13 2 9 22 2" />
      </svg>
    ),
  },
  {
    href: "/?view=archive",
    labelKey: "nav.archive",
    countKey: null,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="21 8 21 21 3 21 3 8" />
        <rect x="1" y="3" width="22" height="5" />
        <line x1="10" y1="12" x2="14" y2="12" />
      </svg>
    ),
  },
];


const settingsItems: MailboxItem[] = [
  {
    href: "/contacts",
    labelKey: "nav.contacts",
    countKey: null,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
        <circle cx="12" cy="7" r="4" />
      </svg>
    ),
  },
  {
    href: "/settings/agents",
    labelKey: "nav.agentSettings",
    countKey: null,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
        <circle cx="12" cy="12" r="3" />
      </svg>
    )
  },
  {
    href: "/settings/audit",
    labelKey: "nav.auditLog",
    countKey: null,
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
];

const mailboxSections: MailboxSection[] = [
  { id: "mail", titleKey: "nav.mail", items: mailItems },
  { id: "settings", titleKey: "nav.settings", items: settingsItems },
];

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

  // Set the browser tab title from the page-level `title` prop.
  // The on-page heading is intentionally absent (Gmail-style chrome)
  // but the <title> element still matters for browser-tab / history
  // / screen-reader use. Subtitle is left out of the tab — it's
  // context copy for humans, not metadata for navigation.
  useEffect(() => {
    if (typeof document === "undefined") return;
    const base = "NexusInbox";
    document.title = title ? `${title} · ${base}` : base;
  }, [title]);

  const sessionQuery = useAuthSessionQuery();
  const agentsQuery = useAgentsQuery();
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
  const agentCount = agentsQuery.data?.agents.length ?? null;
  // 確認が必要 covers held messages and AI drafts (docs/33 §9).
  const draftsQuery = useAgentDraftsQuery();
  const pendingCount =
    pendingQuery.data || draftsQuery.data
      ? (pendingQuery.data?.total ?? 0) + (draftsQuery.data?.drafts?.length ?? 0)
      : null;

  const counts: Record<"inboxUnread" | "agents" | "pending", number | null> = {
    inboxUnread,
    agents: agentCount,
    pending: pendingCount,
  };

  const user = sessionQuery.data?.user;
  const avatarLabel = avatarInitial(user?.display_name ?? user?.id, "?");
  const avatarTooltip = user?.display_name ?? user?.id ?? t("topbar.profile");

  // Pick the longest href that matches activePath so nested routes (e.g.
  // /settings/agents/new) highlight only the most specific entry and don't
  // also light up their parent (/settings/agents).
  const allHrefs = mailboxSections.flatMap((section) =>
    section.items.map((item) => item.href),
  );
  const activeHref = allHrefs
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

  return (
    <div
      className="gmail-shell"
      data-mobile-nav={mobileNavOpen ? "open" : "closed"}
    >
      {/* Post-login animated backdrop. Scope: .ai-app-* / .ai-* only — no
          contact with any gmail-* class. Sits at z-index: 0 behind sidebar
          and main; both are explicitly z-index: 1 so content always wins.
          Internal layout of the backdrop and all colour/motion tuning live
          in AppBackdrop.tsx + globals.css (.ai-app-*). */}
      <AppBackdrop />
      <DisplayNamePrompt />
      <NewVersionNotice />
      {/* Mobile drawer backdrop. Renders only when open; clicking it
          dismisses the drawer. CSS hides it on desktop. */}
      {mobileNavOpen ? (
        <button
          type="button"
          className="mobile-nav-backdrop"
          aria-label={t("nav.closeMenu")}
          onClick={() => setMobileNavOpen(false)}
        />
      ) : null}
      <aside className="gmail-sidebar" id="gmail-sidebar-drawer">
        {/* Logo + wordmark doubles as the home link — Gmail / most
            web apps treat the top-left brand as a click target back
            to the inbox, and users land there expecting it. Wrapping
            the brand in a <Link> rather than putting a separate
            "Home" sidebar item keeps the visual chrome unchanged
            while picking up the affordance. */}
        <Link href="/" className="gmail-brand" aria-label={t("nav.inbox")}>
          <Logo size={44} variant="light" />
          <span className="gmail-brand-text">NexusInbox</span>
        </Link>

        <Link href="/compose" className="compose-pill">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 20h9" />
            <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
          </svg>
          {t("nav.compose")}
        </Link>

        <nav className="mailbox-nav">
          {mailboxSections.map((section) => (
            <div key={section.id} className="mailbox-section">
              <p className="mailbox-section-title">{t(section.titleKey)}</p>
              {section.items.map((item) => {
                const active = item.href === activeHref;
                const className = "mailbox-item" + (active ? " active" : "");
                const liveCount = item.countKey ? counts[item.countKey] : null;
                return (
                  <Link key={item.href} href={item.href} className={className}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      {item.icon}
                      <span>{t(item.labelKey)}</span>
                    </div>
                    {liveCount !== null && liveCount > 0 ? (
                      <span className="mailbox-count" data-testid={`mailbox-count-${item.countKey}`}>
                        {liveCount}
                      </span>
                    ) : null}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>

      <section className="gmail-main">
        {/* Gmail-style minimal chrome: no page-header title/subtitle
            above the search bar. Which section is active is already
            signalled by the sidebar highlight, and any contextual
            copy belongs inside the centre content (not stuck to the
            viewport top). `title` is still used to set the browser
            tab's document.title via the effect below, so browser-
            level navigation still reads cleanly even though the
            heading isn't on-page. `rightAction` is threaded into the
            topbar's action bar just before the global icons, so
            per-page refresh buttons stay one click away. */}
        <header className="gmail-topbar">
          {/* Mobile-only hamburger button. CSS hides it ≥ 980px, where
              the sidebar is permanently visible. On mobile it toggles
              the slide-in drawer. */}
          <button
            type="button"
            className="mobile-nav-toggle"
            aria-label={t("nav.openMenu")}
            aria-expanded={mobileNavOpen}
            aria-controls="gmail-sidebar-drawer"
            onClick={() => setMobileNavOpen((v) => !v)}
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="3" y1="6" x2="21" y2="6" />
              <line x1="3" y1="12" x2="21" y2="12" />
              <line x1="3" y1="18" x2="21" y2="18" />
            </svg>
          </button>
          <div className="search-container">
            <svg className="search-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <input
              className="search-input"
              aria-label={t("topbar.searchLabel")}
              placeholder={searchPlaceholder ?? t("topbar.searchPlaceholder")}
              value={searchValue}
              onChange={(event) => onSearchChange?.(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  onSearchSubmit?.();
                }
              }}
            />
          </div>

          <div className="topbar-actions">
            {/* Per-page action slot (refresh etc). Rendered before
                the global icons so a page-specific reload is
                closer to the search bar than the global help /
                settings links. Some pages don't supply one, in
                which case nothing renders. */}
            {rightAction ? (
              <div className="topbar-page-action">{rightAction}</div>
            ) : null}
            <Link className="icon-btn" href="/help" aria-label={t("topbar.help")}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
            </Link>
            <Link className="icon-btn" href="/settings/agents" aria-label={t("topbar.settings")}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="3" />
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
              </svg>
            </Link>
            <Link className="icon-btn" href="/integrations" aria-label={t("topbar.apps")}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor">
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
            <Link
              className="avatar-btn"
              href="/settings/profile"
              aria-label={t("topbar.profile")}
              title={avatarTooltip}
              data-testid="topbar-avatar"
            >
              {avatarLabel}
            </Link>
            <LanguageSwitcher />
            <AuthLogoutButton />
            {/* Session monitor (redirects to /login on expiry) — hidden from UI */}
            <Suspense fallback={null}>
              <AuthSessionStatus />
            </Suspense>
            {/* WebSocket realtime subscriber — hidden from UI */}
            <Suspense fallback={null}>
              <RealtimeSubscriber />
            </Suspense>
          </div>
        </header>

        <main className="page-content">{children}</main>
      </section>
    </div>
  );
}
