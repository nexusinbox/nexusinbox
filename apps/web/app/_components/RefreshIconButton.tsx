"use client";

import type { ButtonHTMLAttributes } from "react";

type Props = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children" | "className"> & {
  /** Tooltip + aria-label. Each caller passes its own i18n string. */
  label: string;
};

/**
 * Topbar refresh button used as the per-page `rightAction` slot in
 * `AppShell`. Visual style is shared with the existing /inbox refresh
 * (matching `icon-btn` + the same circular-arrow SVG) so that every
 * page exposes the same affordance, instead of mixing icon-only vs
 * "更新する" text buttons across screens.
 */
export function RefreshIconButton({ label, type = "button", ...rest }: Props) {
  return (
    <button
      className="icon-btn"
      type={type}
      title={label}
      aria-label={label}
      {...rest}
    >
      <svg
        width="20"
        height="20"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <polyline points="23 4 23 10 17 10" />
        <polyline points="1 20 1 14 7 14" />
        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10" />
        <path d="M20.49 15A9 9 0 0 1 5.64 18.36L1 14" />
      </svg>
    </button>
  );
}
