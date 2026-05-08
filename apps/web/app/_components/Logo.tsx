/**
 * NexusInbox logo — envelope with connected agent nodes.
 * Two variants: "light" for the main app shell, "dark" for login/concept pages.
 * Colors inspired by the login screen's neon-on-dark aesthetic.
 */
export function Logo({
  size = 28,
  variant = "light",
}: {
  size?: number;
  variant?: "light" | "dark";
}) {
  const id = variant === "light" ? "logo-l" : "logo-d";

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 512 512"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <defs>
        {/* Login-screen inspired gradients */}
        <linearGradient id={`${id}-env`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#7dd7ff" />
          <stop offset="50%" stopColor="#a9b8ff" />
          <stop offset="100%" stopColor="#d49eff" />
        </linearGradient>
        <linearGradient id={`${id}-node`} x1="0.5" y1="0" x2="0.5" y2="1">
          <stop offset="0%" stopColor="#7dd7ff" />
          <stop offset="100%" stopColor="#a9b8ff" />
        </linearGradient>
        {/* Dark backdrop for the login-screen "floating in space" look */}
        <radialGradient id={`${id}-bg`} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#0f1535" />
          <stop offset="100%" stopColor="#0a0c18" />
        </radialGradient>
        {/* Neon glow filter */}
        <filter id={`${id}-glow`} x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Dark rounded background — like the login screen */}
      <rect width="512" height="512" rx="108" fill={`url(#${id}-bg)`} />

      {/* Subtle orbital ring */}
      <circle cx="256" cy="256" r="200" fill="none" stroke="rgba(120,160,255,0.1)" strokeWidth="1.5" strokeDasharray="4 6" />

      {/* Inter-node connections */}
      <line x1="148" y1="120" x2="364" y2="120" stroke="rgba(169,184,255,0.25)" strokeWidth="3" strokeDasharray="6 8" strokeLinecap="round" />
      <line x1="136" y1="136" x2="248" y2="414" stroke="rgba(125,215,255,0.18)" strokeWidth="3" strokeDasharray="6 8" strokeLinecap="round" />
      <line x1="376" y1="136" x2="264" y2="414" stroke="rgba(212,158,255,0.18)" strokeWidth="3" strokeDasharray="6 8" strokeLinecap="round" />

      {/* Envelope body — neon gradient stroke */}
      <rect x="106" y="168" width="300" height="210" rx="24" stroke={`url(#${id}-env)`} strokeWidth="16" strokeLinejoin="round" />

      {/* Envelope flap */}
      <polyline points="106,180 256,308 406,180" stroke={`url(#${id}-env)`} strokeWidth="16" strokeLinecap="round" strokeLinejoin="round" />

      {/* Network nodes with glow */}
      <g filter={`url(#${id}-glow)`}>
        <circle cx="130" cy="120" r="18" fill="#7dd7ff" opacity="0.9" />
        <circle cx="382" cy="120" r="18" fill="#a9b8ff" opacity="0.9" />
        <circle cx="256" cy="430" r="18" fill="#d49eff" opacity="0.9" />
      </g>

      {/* Node-to-envelope connections */}
      <line x1="130" y1="138" x2="140" y2="168" stroke="#7dd7ff" strokeWidth="6" strokeLinecap="round" opacity="0.6" />
      <line x1="382" y1="138" x2="372" y2="168" stroke="#a9b8ff" strokeWidth="6" strokeLinecap="round" opacity="0.6" />
      <line x1="256" y1="412" x2="256" y2="378" stroke="#d49eff" strokeWidth="6" strokeLinecap="round" opacity="0.6" />
    </svg>
  );
}
