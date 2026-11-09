// No shared agent at this address (sharing off, or a wrong link).
import type { Metadata } from "next";
import { translate } from "../../../lib/i18n/translate";
import { PublicAgentView } from "./PublicAgentView";

export const metadata: Metadata = {
  title: translate("ja", "publicAgent.notFoundTitle"),
  robots: { index: false, follow: false },
};

export default function PublicAgentNotFound() {
  return <PublicAgentView state={{ kind: "missing" }} />;
}
