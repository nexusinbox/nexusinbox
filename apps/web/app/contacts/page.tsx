"use client";

import { FormEvent, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AppShell } from "../_components/AppShell";
import { RefreshIconButton } from "../_components/RefreshIconButton";
import {
  useContactsQuery,
  useCreateContactMutation,
  useDeleteContactMutation,
  useUpdateContactMutation,
} from "../../lib/api/hooks";
import { useTwoColumnResize } from "../../lib/ui/useTwoColumnResize";
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
  const createContact = useCreateContactMutation();
  const updateContact = useUpdateContactMutation();
  const deleteContact = useDeleteContactMutation();

  const { layoutStyle, startResize } = useTwoColumnResize({
    storageKey: "nexusinbox.contacts.thread_width.v1",
    initialWidth: 360,
  });

  const contacts = useMemo<ContactEntry[]>(
    () => contactsQuery.data?.contacts ?? [],
    [contactsQuery.data],
  );

  const [activeId, setActiveId] = useState<string | "new">("new");
  const [draft, setDraft] = useState<DraftState>(emptyDraft);
  const [status, setStatus] = useState<StatusState>(null);
  const [appliedPrefill, setAppliedPrefill] = useState<string>("");

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
  // that Effect A just populated from `?add=<did>` (that used to race and
  // reset the prefill — see docs/plan comments above).
  useEffect(() => {
    if (activeId === "new") return;
    const selected = contacts.find((contact) => contact.id === activeId);
    if (!selected) {
      setActiveId("new");
      return;
    }
    setDraft({
      did: selected.did,
      person_name: selected.person_name,
      agent_label: selected.agent_label ?? "",
      note: selected.note ?? "",
    });
  }, [activeId, contacts]);

  const isEditing = activeId !== "new";

  const handleSelect = (id: string | "new") => {
    setStatus(null);
    // When the user explicitly switches from an existing contact back to
    // the "new" tile, clear the draft. Effect B no longer does this so we
    // do it here — but only on user interaction, never for URL-driven
    // prefills.
    if (id === "new" && activeId !== "new") {
      setDraft(emptyDraft);
    }
    setActiveId(id);
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
          body: {
            person_name: personName,
            agent_label: agentLabel.length > 0 ? agentLabel : null,
            note: note.length > 0 ? note : null,
          },
        });
        setStatus({ kind: "success", message: t("contacts.updated") });
      } else {
        const created = await createContact.mutateAsync({
          did,
          person_name: personName,
          agent_label: agentLabel.length > 0 ? agentLabel : null,
          note: note.length > 0 ? note : null,
        });
        setStatus({ kind: "success", message: t("contacts.added") });
        setActiveId(created.id);
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : t("contacts.saveFailed");
      setStatus({ kind: "error", message: msg });
    }
  };

  const handleDelete = async () => {
    if (!isEditing) return;
    if (!window.confirm(t("contacts.confirmDelete"))) return;
    try {
      await deleteContact.mutateAsync(activeId);
      setStatus({ kind: "success", message: t("contacts.deleted") });
      setActiveId("new");
    } catch (error) {
      const msg = error instanceof Error ? error.message : t("contacts.deleteFailed");
      setStatus({ kind: "error", message: msg });
    }
  };

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
      <section className="mail-layout" style={layoutStyle}>
        <aside className="thread-list">
          <article
            className={"card-item" + (activeId === "new" ? " active" : "")}
            onClick={() => handleSelect("new")}
          >
            <p className="card-title">{t("contacts.addNew")}</p>
            <p className="card-sub">{t("contacts.addNewDesc")}</p>
          </article>
          {contacts.length === 0 ? (
            <div className="empty-state">{t("contacts.empty")}</div>
          ) : (
            contacts.map((contact) => {
              const className = "card-item" + (activeId === contact.id ? " active" : "");
              return (
                <article
                  className={className}
                  key={contact.id}
                  onClick={() => handleSelect(contact.id)}
                >
                  <p className="card-title">{contact.person_name}</p>
                  <p className="card-sub">
                    {contact.agent_label ? contact.agent_label + " · " : ""}
                    {contact.did}
                  </p>
                  {contact.note ? <p className="card-meta">{contact.note}</p> : null}
                </article>
              );
            })
          )}
        </aside>

        <div className="mail-resizer" onMouseDown={startResize} />

        <article className="reader-pane" style={{ borderRight: "none" }}>
          <div className="compose-scroll">
            <section className="compose-frame">
              <header className="compose-head">
                <span>{isEditing ? t("contacts.formEditTitle") : t("contacts.formNewTitle")}</span>
                <span className="badge">{t("contacts.formBadge")}</span>
              </header>
              <div className="compose-body">
                <form className="form-grid" onSubmit={handleSubmit}>
                  <div className="field">
                    <label className="field-label" htmlFor="contact-did">
                      {t("contacts.didLabel")}
                    </label>
                    <input
                      id="contact-did"
                      className="input"
                      value={draft.did}
                      onChange={(event) =>
                        setDraft((prev) => ({ ...prev, did: event.target.value }))
                      }
                      placeholder={t("contacts.didPlaceholder")}
                      disabled={isEditing}
                      autoComplete="off"
                    />
                    <p className="field-help">
                      {t("contacts.didHelp")}
                    </p>
                  </div>

                  <div className="field">
                    <label className="field-label" htmlFor="contact-name">
                      {t("contacts.nameLabel")}
                    </label>
                    <input
                      id="contact-name"
                      className="input"
                      value={draft.person_name}
                      onChange={(event) =>
                        setDraft((prev) => ({ ...prev, person_name: event.target.value }))
                      }
                      placeholder={t("contacts.namePlaceholder")}
                      maxLength={64}
                    />
                    <p className="field-help">
                      {t("contacts.nameHelp")}
                    </p>
                  </div>

                  <div className="field">
                    <label className="field-label" htmlFor="contact-agent-label">
                      {t("contacts.agentNameLabel")}
                    </label>
                    <input
                      id="contact-agent-label"
                      className="input"
                      value={draft.agent_label}
                      onChange={(event) =>
                        setDraft((prev) => ({ ...prev, agent_label: event.target.value }))
                      }
                      placeholder={t("contacts.agentNamePlaceholder")}
                      maxLength={64}
                    />
                    <p className="field-help">
                      {t("contacts.agentNameHelp")}
                    </p>
                  </div>

                  <div className="field">
                    <label className="field-label" htmlFor="contact-note">
                      {t("contacts.memoLabel")}
                    </label>
                    <textarea
                      id="contact-note"
                      className="textarea"
                      value={draft.note}
                      onChange={(event) =>
                        setDraft((prev) => ({ ...prev, note: event.target.value }))
                      }
                      placeholder={t("contacts.memoPlaceholder")}
                      maxLength={500}
                    />
                  </div>

                  {status ? (
                    <div className={`form-status ${status.kind}`} role="status">
                      {status.message}
                    </div>
                  ) : null}

                  <div className="form-actions">
                    {isEditing ? (
                      <button
                        type="button"
                        className="btn"
                        onClick={handleDelete}
                        disabled={deleteContact.isPending}
                      >
                        {deleteContact.isPending ? t("contacts.deleting") : t("contacts.deleteBtn")}
                      </button>
                    ) : null}
                    <button
                      type="submit"
                      className="btn primary"
                      disabled={createContact.isPending || updateContact.isPending}
                    >
                      {createContact.isPending || updateContact.isPending
                        ? t("contacts.savingBtn")
                        : isEditing
                          ? t("contacts.saveBtn")
                          : t("contacts.addBtn")}
                    </button>
                  </div>
                </form>
              </div>
            </section>
          </div>
        </article>
      </section>
    </AppShell>
  );
}
