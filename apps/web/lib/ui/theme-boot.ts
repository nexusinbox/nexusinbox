// Shared by the theme hook (client) and the root layout (server), so it is
// not a "use client" module.

export const THEME_STORAGE_KEY = "nexusinbox.theme";

/** Runs in <head> before paint so a dark device never flashes light. */
export const THEME_BOOT_SCRIPT = `(function(){try{var c=localStorage.getItem(${JSON.stringify(
  THEME_STORAGE_KEY,
)});var d=c==="dark"||(c!=="light"&&matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.dataset.theme=d?"dark":"light";}catch(e){}})();`;
