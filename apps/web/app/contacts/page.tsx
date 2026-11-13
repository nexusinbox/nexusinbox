"use client";

// コンタクト (docs/35 step 4): a searchable list with a face per contact,
// row actions, and the add / edit form opened in place.

import Link from "next/link";
import { FormEvent, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ContactsTabs } from "./ContactsTabs";
import { AppShell } from "../_components/AppShell";
import { RefreshIconButton } from "../_components/RefreshIconButton";
import { ConfirmationPanel } from "../_components/ConfirmationPanel";
import { Avatar } from "../_components/messages/ConversationView";
import {
  useAgentsQuery,
  useContactsQuery,
  useCreateContactMutation,
  useDeleteContactMutation,
  useResetContactsKeyMutation,
  useUpdateContactMutation,
} from "../../lib/api/hooks";
import { useTranslation } from "../../lib/i18n";
import type { ContactEntry } from "../../lib/api/types";

type DraftState = {
  did: string;
  person_name: string;
  agent_label: string;
  note: string;
};

type StatusState = { kind: "info" | "error" | "success"; message: string } | null;

const emptyDraft: DraftState = {
  did: "",
  person_name: "",
  agent_label: "",
  note: "",
};

export default function ContactsPage() {
  return (
    <Suspense fallback={null}>
      <ContactsPageInner />
    </Suspense>
  );
}

function ContactsPageInner() {
  const { t } = useTranslation();
  const searchParams = useSearchParams();
  const prefillDid = searchParams?.get("add")?.trim() ?? "";
  const contactsQuery = useContactsQuery();
  const agentsQuery = useAgentsQuery();
  const createContact = useCreateContactMutation();
  const updateContact = useUpdateContactMutation();
  const deleteContact = useDeleteContactMutation();
  const resetContactsKey = useResetContactsKeyMutation();

  const contacts = useMemo<ContactEntry[]>(
    () => contactsQuery.data?.contacts ?? [],
    [contactsQuery.data],
  );
  const agents = agentsQuery.data?.agents ?? [];
  // Which of the person's agents the confirmation number is made with.
  const [confirmAs, setConfirmAs] = useState<string | null>(null);
  const confirmAgent = agents.find((a) => a.did === confirmAs) ?? agents[0];
  // Names and notes are sealed with a key this device may not hold.
  const locked = contactsQuery.data?.keyState === "locked";
  const canReset = contactsQuery.data?.canReset ?? false;

  // null: no form open; "new": the add form; otherwise the contact being edited.
  const [activeId, setActiveId] = useState<string | "new" | null>(null);
  const [draft, setDraft] = useState<DraftState>(emptyDraft);
  const [status, setStatus] = useState<StatusState>(null);
  const [appliedPrefill, setAppliedPrefill] = useState<string>("");
  const [query, setQuery] = useState("");

  // When the page opens with ?add=<did>, either switch to the
  // existing contact for that DID or seed the "new" form with it.
  // Runs once per distinct prefill value so edits aren't clobbered.
  useEffect(() => {
    if (!prefillDid) return;
    if (appliedPrefill === prefillDid) return;
    if (contactsQuery.isPending) return;

    const existing = contacts.find((contact) => contact.did === prefillDid);
    if (existing) {
      setActiveId(existing.id);
    } else {
      setActiveId("new");
      setDraft({ ...emptyDraft, did: prefillDid });
    }
    setAppliedPrefill(prefillDid);
  }, [prefillDid, appliedPrefill, contacts, contactsQuery.isPending]);

  // Sync draft with the currently selected contact. Intentionally returns
  // early for activeId === "new" so this effect can never clobber a draft
  // that the effect above just populated from `?add=<did>`.
  useEffect(() => {
    if (activeId === null || activeId === "new") return;
    const selected = contacts.find((contact) => contact.id === activeId);
    if (!selected) {
      setActiveId(null);
      return;
    }
    setDraft({
      did: selected.did,
      person_name: selected.person_name,
      agent_label: selected.agent_label ?? "",
      note: selected.note ?? "",
    });
  }, [activeId, contacts]);

  const isEditing = activeId !== null && activeId !== "new";
  const selectedContact = isEditing ? contacts.find((contact) => contact.id === activeId) : undefined;
  const selectedUnreadable = selectedContact ? !selectedContact.readable : false;
  const formDisabled = locked || selectedUnreadable;

  const displayName = (contact: ContactEntry): string => {
    if (!contact.readable) return t("contacts.unreadableTitle");
    const agent = contact.agent_label?.trim();
    return agent
      ? t("messages.partyName", { person: contact.person_name, agent })
      : contact.person_name;
  };

  const needle = query.trim().toLowerCase();
  const visible = needle
    ? contacts.filter((contact) =>
        [displayName(contact), contact.person_name, contact.agent_label ?? "", contact.note ?? "", contact.did]
          .some((text) => text.toLowerCase().includes(needle)),
      )
    : contacts;

  // One agent: open the conversation from it. Several: the 新しい会話
  // picker, with this contact already filtered, lets the person choose.
  const messageHref = (did: string): string =>
    agents.length === 1
      ? `/?with=${encodeURIComponent(did)}&as=${encodeURIComponent(agents[0].did)}`
      : `/compose?with=${encodeURIComponent(did)}`;

  const openNew = () => {
    setStatus(null);
    setDraft(emptyDraft);
    setActiveId("new");
  };

  const openEdit = (id: string) => {
    setStatus(null);
    setActiveId(id);
  };

  const closeForm = () => {
    setActiveId(null);
    setDraft(emptyDraft);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setStatus(null);

    const did = draft.did.trim();
    const personName = draft.person_name.trim();
    const agentLabel = draft.agent_label.trim();
    const note = draft.note.trim();

    if (!personName) {
      setStatus({ kind: "error", message: t("contacts.validationName") });
      return;
    }
    if (!isEditing && !did.startsWith("did:key:")) {
      setStatus({ kind: "error", message: t("contacts.validationDid") });
      return;
    }

    try {
      if (isEditing) {
        await updateContact.mutateAsync({
          id: activeId,
          did: draft.did,
          body: {
            person_name: personName,
            agent_label: agentLabel.length > 0 ? agentLabel : null,
            note: note.length > 0 ? note : null,
          },
        });
        setStatus({ kind: "success", message: t("contacts.updated") });
      } else {
        await createContact.mutateAsync({
          did,
          person_name: personName,
          agent_label: agentLabel.length > 0 ? agentLabel : null,
          note: note.length > 0 ? note : null,
        });
        setStatus({ kind: "success", message: t("contacts.added") });
      }
      closeForm();
    } catch (error) {
      const msg = error instanceof Error ? error.message : t("contacts.saveFailed");
      setStatus({ kind: "error", message: msg });
    }
  };

  const handleResetKey = async () => {
    if (!window.confirm(t("contacts.confirmResetKey"))) return;
    try {
      await resetContactsKey.mutateAsync();
      setStatus({ kind: "success", message: t("contacts.resetKeyDone") });
    } catch {
      setStatus({ kind: "error", message: t("contacts.resetKeyFailed") });
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm(t("contacts.confirmDelete"))) return;
    setStatus(null);
    try {
      await deleteContact.mutateAsync(id);
      setStatus({ kind: "success", message: t("contacts.deleted") });
      if (activeId === id) closeForm();
    } catch (error) {
      const msg = error instanceof Error ? error.message : t("contacts.deleteFailed");
      setStatus({ kind: "error", message: msg });
    }
  };

  const saving = createContact.isPending || updateContact.isPending;

  const form = (
    <form className="ct-form" onSubmit={handleSubmit}>
      <h2 className="ct-form-title">
        {isEditing ? t("contacts.formEditTitle") : t("contacts.formNewTitle")}
      </h2>
      <p className="ct-help">
        {selectedUnreadable ? t("contacts.unreadableHelp") : t("contacts.sealedHelp")}
      </p>

      <label className="ap-field" htmlFor="contact-name">
        {t("contacts.nameLabel")}
        <input
          id="contact-name"
          className="input"
          value={draft.person_name}
          onChange={(event) => setDraft((prev) => ({ ...prev, person_name: event.target.value }))}
          placeholder={t("contacts.namePlaceholder")}
          maxLength={64}
          disabled={formDisabled}
        />
        <span className="ct-help">{t("contacts.nameHelp")}</span>
      </label>

      <label className="ap-field" htmlFor="contact-agent-label">
        {t("contacts.agentNameLabel")}
        <input
          id="contact-agent-label"
          className="input"
          value={draft.agent_label}
          onChange={(event) => setDraft((prev) => ({ ...prev, agent_label: event.target.value }))}
          placeholder={t("contacts.agentNamePlaceholder")}
          maxLength={64}
          disabled={formDisabled}
        />
        <span className="ct-help">{t("contacts.agentNameHelp")}</span>
      </label>

      <label className="ap-field" htmlFor="contact-note">
        {t("contacts.memoLabel")}
        <textarea
          id="contact-note"
          className="input"
          value={draft.note}
          onChange={(event) => setDraft((prev) => ({ ...prev, note: event.target.value }))}
          placeholder={t("contacts.memoPlaceholder")}
          maxLength={500}
          rows={2}
          disabled={formDisabled}
        />
      </label>

      <label className="ap-field" htmlFor="contact-did">
        {t("contacts.didLabel")}
        <input
          id="contact-did"
          className="input ct-mono"
          value={draft.did}
          onChange={(event) => setDraft((prev) => ({ ...prev, did: event.target.value }))}
          placeholder={t("contacts.didPlaceholder")}
          disabled={isEditing || formDisabled}
          autoComplete="off"
        />
        <span className="ct-help">{t("contacts.didHelp")}</span>
      </label>

      {selectedContact?.readable && confirmAgent ? (
        <div>
          {agents.length > 1 ? (
            <select
              className="input"
              style={{ marginTop: 8 }}
              value={confirmAgent.did}
              onChange={(event) => setConfirmAs(event.target.value)}
              aria-label={t("confirm.title")}
            >
              {agents.map((a) => (
                <option key={a.did} value={a.did}>
                  {a.label}
                </option>
              ))}
            </select>
          ) : null}
          <ConfirmationPanel
            key={`${selectedContact.id}:${confirmAgent.did}`}
            counterpart={selectedContact.aid ?? selectedContact.did}
            name={displayName(selectedContact)}
            ownAgent={confirmAgent}
            contact={selectedContact}
          />
        </div>
      ) : null}

      {status?.kind === "error" ? (
        <p className="ct-status error" role="status">
          {status.message}
        </p>
      ) : null}

      <div className="dm-btns">
        <button type="submit" className="dm-btn accent" disabled={saving || formDisabled}>
          {saving
            ? t("contacts.savingBtn")
            : isEditing
              ? t("contacts.saveBtn")
              : t("contacts.addBtn")}
        </button>
        <button type="button" className="dm-btn" onClick={closeForm}>
          {t("contacts.cancelBtn")}
        </button>
      </div>
    </form>
  );

  return (
    <AppShell
      title={t("contacts.title")}
      activePath="/contacts"
      rightAction={
        <RefreshIconButton
          onClick={() => contactsQuery.refetch()}
          label={t("contacts.refresh")}
        />
      }
    >
      <div className="ct">
        <ContactsTabs active="contacts" />
        <div className="ct-top">
          <input
            className="nc-input"
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("contacts.searchPlaceholder")}
            aria-label={t("contacts.searchPlaceholder")}
            autoComplete="off"
            data-testid="contacts-search"
          />
          <button
            type="button"
            className="dm-btn accent"
            onClick={openNew}
            disabled={activeId === "new"}
            data-testid="contacts-add"
          >
            {t("contacts.addNew")}
          </button>
        </div>

        {locked ? (
          <div className="ct-notice" role="status">
            <p>{t("contacts.lockedNotice")}</p>
            {canReset ? (
              <>
                <p>{t("contacts.lockedResetHint")}</p>
                <button
                  type="button"
                  className="dm-btn"
                  onClick={handleResetKey}
                  disabled={resetContactsKey.isPending}
                >
                  {t("contacts.resetKeyBtn")}
                </button>
              </>
            ) : null}
          </div>
        ) : null}

        {status && status.kind !== "error" ? (
          <p className="ct-status" role="status">
            {status.message}
          </p>
        ) : status && activeId === null ? (
          <p className="ct-status error" role="status">
            {status.message}
          </p>
        ) : null}

        {activeId === "new" ? <div className="ct-form-wrap">{form}</div> : null}

        {contactsQuery.isPending ? (
          <p className="dm-empty">{t("contacts.loading")}</p>
        ) : contactsQuery.isError ? (
          <p className="dm-empty">{t("contacts.loadFailed")}</p>
        ) : contacts.length === 0 ? (
          <p className="dm-empty">{t("contacts.empty")}</p>
        ) : visible.length === 0 ? (
          <p className="dm-empty">{t("contacts.noMatch")}</p>
        ) : (
          visible.map((contact) => {
            const name = displayName(contact);
            return (
              <div key={contact.id}>
                <div className="ct-row" data-testid="contact-row">
                  <Avatar did={contact.did} name={contact.readable ? contact.person_name : "?"} />
                  <div className="dm-row-body">
                    <span className="dm-name">{name}</span>
                    {contact.note ? <span className="ct-note">{contact.note}</span> : null}
                  </div>
                  <div className="ct-actions">
                    <Link href={messageHref(contact.did)} className="dm-btn accent ct-send">
                      {t("contacts.sendMessage")}
                    </Link>
                    <button
                      type="button"
                      className="dm-icon-btn"
                      onClick={() => (activeId === contact.id ? closeForm() : openEdit(contact.id))}
                      aria-label={t("contacts.editBtn")}
                      aria-expanded={activeId === contact.id}
                      title={t("contacts.editBtn")}
                    >
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M12 20h9" />
                        <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z" />
                      </svg>
                    </button>
                    <button
                      type="button"
                      className="dm-icon-btn ct-danger"
                      onClick={() => handleDelete(contact.id)}
                      disabled={deleteContact.isPending}
                      aria-label={t("contacts.deleteBtn")}
                      title={t("contacts.deleteBtn")}
                    >
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <polyline points="3 6 5 6 21 6" />
                        <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
                        <path d="M10 11v6M14 11v6M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
                      </svg>
                    </button>
                  </div>
                </div>
                {activeId === contact.id ? <div className="ct-form-wrap">{form}</div> : null}
              </div>
            );
          })
        )}
      </div>
    </AppShell>
  );
}
