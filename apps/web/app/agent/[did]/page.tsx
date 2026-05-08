import { NexusInboxClient } from "./NexusInboxClient";

type AgentPageProps = {
  params: Promise<{ did: string }>;
};

export default async function NexusInboxPage({ params }: AgentPageProps) {
  const { did } = await params;
  return <NexusInboxClient did={decodeURIComponent(did)} />;
}
