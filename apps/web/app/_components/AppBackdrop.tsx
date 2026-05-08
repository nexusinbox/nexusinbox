"use client";

/**
 * NexusInbox — Post-login animated backdrop.
 *
 * Layers (back → front):
 *   1. Radial wash (cyan top-left, violet bottom-right) — sets the palette
 *   2. Two drifting blurred orbs
 *   3. AgentOrbits SVG — 2 orbital rigs with agent nodes + relay signal
 *   4. AgentMesh SVG — rotating triangle mesh w/ radar sweep (from login)
 *   5. ConicRings — 3 thin conic-gradient rings drifting at screen edges
 *   6. Constellation SVG — scattered twinkling dots with dashed edges
 *   7. ScanBeam — horizontal beam sweeping top → bottom
 *   8. Dot grid with radial mask
 *
 * All layers are decorative and carry `aria-hidden` so assistive tech
 * ignores them. The entire backdrop is `pointer-events: none` so it
 * never steals clicks from the panels rendered above.
 *
 * The `calm` prop toggles `.is-calm` on the root, which disables every
 * animation and drops the mesh/conic opacities for users who want a
 * static background without going as far as `prefers-reduced-motion`.
 * OS-level "reduce motion" is honoured separately in `globals.css`.
 */
export function AppBackdrop({ calm = false }: { calm?: boolean }) {
  const rootClass = `ai-app-bg${calm ? " is-calm" : ""}`;
  return (
    <div className={rootClass} aria-hidden>
      <div className="ai-app-bg-wash" />
      <div className="ai-app-orb ai-app-orb-a" />
      <div className="ai-app-orb ai-app-orb-b" />
      <AgentOrbits />
      <AgentMesh />
      <ConicRings />
      <Constellation />
      <div className="ai-app-scanbeam" />
      <div className="ai-app-bg-grid" />
    </div>
  );
}

function AgentOrbits() {
  return (
    <svg
      className="ai-app-orbits"
      viewBox="0 0 1600 1000"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden
    >
      <defs>
        <radialGradient id="ai-app-node-cy" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0%" stopColor="rgba(125,215,255,0.9)" />
          <stop offset="100%" stopColor="rgba(125,215,255,0)" />
        </radialGradient>
        <radialGradient id="ai-app-node-pe" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0%" stopColor="rgba(169,184,255,0.9)" />
          <stop offset="100%" stopColor="rgba(169,184,255,0)" />
        </radialGradient>
        <radialGradient id="ai-app-node-vi" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0%" stopColor="rgba(212,158,255,0.9)" />
          <stop offset="100%" stopColor="rgba(212,158,255,0)" />
        </radialGradient>
      </defs>

      <g transform="translate(1180 300)">
        <circle
          r="180"
          fill="none"
          stroke="rgba(125,215,255,0.08)"
          strokeWidth="1"
          strokeDasharray="2 10"
        />
        <circle
          r="120"
          fill="none"
          stroke="rgba(125,215,255,0.05)"
          strokeWidth="1"
          strokeDasharray="2 14"
        />
        <g className="ai-orbit-a">
          <circle cx="180" cy="0" r="28" fill="url(#ai-app-node-cy)" />
          <circle cx="180" cy="0" r="3" fill="#7dd7ff" />
        </g>
        <g className="ai-orbit-b">
          <circle cx="120" cy="0" r="20" fill="url(#ai-app-node-pe)" />
          <circle cx="120" cy="0" r="2.5" fill="#a9b8ff" />
        </g>
      </g>

      <g transform="translate(260 760)">
        <circle
          r="200"
          fill="none"
          stroke="rgba(212,158,255,0.06)"
          strokeWidth="1"
          strokeDasharray="3 12"
        />
        <g className="ai-orbit-c">
          <circle cx="200" cy="0" r="30" fill="url(#ai-app-node-vi)" />
          <circle cx="200" cy="0" r="3" fill="#d49eff" />
        </g>
      </g>

      {/* Relay line — pulses a signal between two orbital rigs. */}
      <g>
        <line
          x1="260"
          y1="760"
          x2="1180"
          y2="300"
          stroke="rgba(169,184,255,0.08)"
          strokeWidth="1"
          strokeDasharray="4 10"
        />
        <circle className="ai-relay-pulse" r="4" fill="#a9b8ff">
          <animateMotion
            dur="7s"
            repeatCount="indefinite"
            path="M 260 760 L 1180 300"
          />
        </circle>
        <circle className="ai-relay-pulse" r="3" fill="#7dd7ff">
          <animateMotion
            dur="9s"
            begin="-3s"
            repeatCount="indefinite"
            path="M 1180 300 L 260 760"
          />
        </circle>
      </g>
    </svg>
  );
}

/**
 * Rotating triangular agent mesh — lifted from the /login stage and
 * re-tuned for the light shell (lower opacities, whiter strokes). Drifts
 * behind the mail panels at top-center. Gradient ids are prefixed to
 * avoid collision with `/login`'s own <defs>.
 */
function AgentMesh() {
  const nodes: Array<[number, number, string]> = [
    [0, -180, "#7dd7ff"],
    [156, 90, "#a9b8ff"],
    [-156, 90, "#d49eff"],
  ];
  return (
    <svg className="ai-app-mesh" viewBox="-300 -300 600 600" aria-hidden>
      <defs>
        <radialGradient id="ai-app-radar" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0%" stopColor="rgba(125,215,255,0.35)" />
          <stop offset="100%" stopColor="rgba(125,215,255,0)" />
        </radialGradient>
      </defs>
      <g className="ai-app-mesh-rot">
        <circle
          r="260"
          fill="none"
          stroke="rgba(120,160,255,0.35)"
          strokeWidth="1.3"
          strokeDasharray="4 8"
        />
        <circle
          r="180"
          fill="none"
          stroke="rgba(120,160,255,0.25)"
          strokeWidth="1.2"
          strokeDasharray="2 10"
        />
        {nodes.map(([x, y, c], i) => (
          <g key={i} transform={`translate(${x} ${y})`}>
            <circle r="22" fill={c} opacity="0.35" />
            <circle r="7" fill={c} opacity="1" />
          </g>
        ))}
        <line
          x1="0"
          y1="-180"
          x2="156"
          y2="90"
          stroke="rgba(169,184,255,0.75)"
          strokeWidth="1.3"
          strokeDasharray="4 8"
        />
        <line
          x1="156"
          y1="90"
          x2="-156"
          y2="90"
          stroke="rgba(212,158,255,0.75)"
          strokeWidth="1.3"
          strokeDasharray="4 8"
        />
        <line
          x1="-156"
          y1="90"
          x2="0"
          y2="-180"
          stroke="rgba(125,215,255,0.75)"
          strokeWidth="1.3"
          strokeDasharray="4 8"
        />
        <g className="ai-app-mesh-sweep">
          <path
            d="M 0 0 L 260 0 A 260 260 0 0 1 184 184 Z"
            fill="url(#ai-app-radar)"
            opacity="0.6"
          />
        </g>
      </g>
    </svg>
  );
}

/**
 * Three conic-gradient rings at different screen anchors, each rotating
 * at its own cadence. DOM elements (not SVG) so the CSS mask trick that
 * punches the inner disc out of each ring lands on all browsers.
 */
function ConicRings() {
  return (
    <div className="ai-app-conics" aria-hidden>
      <span className="ai-conic ai-conic-a" />
      <span className="ai-conic ai-conic-b" />
      <span className="ai-conic ai-conic-c" />
    </div>
  );
}

/**
 * Scattered dots with thin dashed edges. Positions are hand-tuned to sit
 * in the negative space around the mail panels (top strip, right rail,
 * bottom strip, left rail).
 */
function Constellation() {
  const nodes: Array<[number, number]> = [
    // top strip
    [120, 80],
    [240, 56],
    [360, 110],
    [520, 72],
    [660, 44],
    [780, 96],
    [900, 62],
    [1040, 104],
    [1180, 66],
    [1340, 98],
    [1480, 56],
    // right rail
    [1500, 220],
    [1430, 340],
    [1520, 460],
    [1440, 580],
    [1530, 700],
    [1460, 820],
    // bottom strip
    [140, 920],
    [320, 960],
    [500, 920],
    [680, 956],
    [860, 918],
    [1040, 948],
    [1220, 920],
    [1400, 950],
    // left rail
    [60, 260],
    [90, 420],
    [50, 560],
    [100, 700],
    [60, 860],
  ];
  const edges: Array<[number, number]> = [
    [0, 1],
    [1, 2],
    [2, 3],
    [3, 4],
    [4, 5],
    [5, 6],
    [6, 7],
    [7, 8],
    [8, 9],
    [9, 10],
    [10, 11],
    [11, 12],
    [12, 13],
    [13, 14],
    [14, 15],
    [15, 16],
    [17, 18],
    [18, 19],
    [19, 20],
    [20, 21],
    [21, 22],
    [22, 23],
    [23, 24],
    [25, 26],
    [26, 27],
    [27, 28],
    [28, 29],
    // cross-links
    [0, 29],
    [10, 11],
    [16, 17],
    [24, 25],
  ];
  return (
    <svg
      className="ai-app-constellation"
      viewBox="0 0 1600 1000"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden
    >
      <g className="ai-constell-edges">
        {edges.map(([a, b], i) => (
          <line
            key={i}
            x1={nodes[a][0]}
            y1={nodes[a][1]}
            x2={nodes[b][0]}
            y2={nodes[b][1]}
            stroke="rgba(100,140,220,0.55)"
            strokeWidth="1.2"
            strokeDasharray="2 6"
          />
        ))}
      </g>
      <g className="ai-constell-nodes">
        {nodes.map(([x, y], i) => (
          <circle
            key={i}
            cx={x}
            cy={y}
            r="2.4"
            fill="rgba(100,140,220,0.95)"
            style={{ animationDelay: `${(i * 0.31) % 6}s` }}
          />
        ))}
      </g>
    </svg>
  );
}
