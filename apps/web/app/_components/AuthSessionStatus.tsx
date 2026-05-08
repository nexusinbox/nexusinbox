"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef } from "react";

import { useAuthSessionQuery } from "../../lib/api/hooks";

export function AuthSessionStatus() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const redirectedRef = useRef(false);
  // Share the same queryKey/queryFn as the rest of the app
  // (AppShell, profile, etc.) so only one /auth/session request is
  // in flight and its result drives every consumer.
  const sessionQuery = useAuthSessionQuery();

  useEffect(() => {
    if (redirectedRef.current) return;
    if (sessionQuery.isPending) return;
    // Only redirect when the server *confirms* the session is gone.
    // A network error or transient 5xx leaves `data` undefined — in
    // that case we stay on the page and let the next refetch decide,
    // rather than bouncing to /login and losing context.
    if (sessionQuery.data === undefined) return;
    if (sessionQuery.data.authenticated) return;

    const currentSearch = searchParams?.toString();
    const nextPath = currentSearch ? `${pathname}?${currentSearch}` : pathname;
    redirectedRef.current = true;
    router.replace(`/login?next=${encodeURIComponent(nextPath)}`);
    router.refresh();
  }, [pathname, router, searchParams, sessionQuery.data, sessionQuery.isPending]);

  // This component handles session monitoring and redirect logic only.
  // No visible UI is rendered — status is implicit from the avatar.
  return null;
}
