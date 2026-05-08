import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

// IDKit (@worldcoin/idkit) pulls in WalletConnect, which executes
// `new Function()` at initialisation. That forces the page's CSP
// to allow 'unsafe-eval', which negates most of the nonce +
// strict-dynamic XSS protection. To keep that tax isolated, IDKit
// lives only inside /login/idkit and gets iframe'd from the parent
// /login — every other route runs eval-free.
//
// This rule guards the invariant: any new import of @worldcoin/idkit
// outside the allow-listed files fails CI. The only places allowed
// are the isolation sub-route itself and the pure-type helper in
// lib/world/idkit.ts (which imports *types only*).
const IDKIT_RESTRICTION = {
  paths: [
    {
      name: "@worldcoin/idkit",
      message:
        "IDKit must only be imported from apps/web/app/login/idkit/**. Embed /login/idkit via iframe instead of adding a new import site. See CONTRIBUTING.md → Security-sensitive changes.",
    },
  ],
};

export default [
  {
    ignores: ["node_modules/**", ".next/**", "dist/**", "coverage/**", "target/**", "**/next-env.d.ts"],
  },
  {
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "no-restricted-imports": ["error", IDKIT_RESTRICTION],
    },
  },
  {
    // Allow-list: the IDKit isolation sub-route and the pure type
    // helper. Both are audited to either stay inside the iframe or
    // avoid importing runtime eval code.
    files: [
      "apps/web/app/login/idkit/**/*.ts",
      "apps/web/app/login/idkit/**/*.tsx",
      "apps/web/lib/world/idkit.ts",
      "apps/web/lib/world/idkit.test.ts",
    ],
    rules: {
      "no-restricted-imports": "off",
    },
  },
];
