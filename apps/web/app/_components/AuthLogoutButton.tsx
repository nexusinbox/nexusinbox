"use client";

import { useRouter } from "next/navigation";
import { useAuthLogoutMutation } from "../../lib/api/hooks";

export function AuthLogoutButton() {
  const router = useRouter();
  const logout = useAuthLogoutMutation();

  const handleLogout = async () => {
    try {
      await logout.mutateAsync();
    } finally {
      router.replace("/login");
      router.refresh();
    }
  };

  return (
    <button className="icon-btn" type="button" aria-label="ログアウト" title="ログアウト" onClick={handleLogout}>
      {logout.isPending ? (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.4 }}>
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
          <polyline points="16 17 21 12 16 7" />
          <line x1="21" y1="12" x2="9" y2="12" />
        </svg>
      ) : (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
          <polyline points="16 17 21 12 16 7" />
          <line x1="21" y1="12" x2="9" y2="12" />
        </svg>
      )}
    </button>
  );
}
