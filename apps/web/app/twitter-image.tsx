// Twitter wants its own meta line (twitter:image), distinct from og:image.
// We emit the same artwork as opengraph-image — kept as a thin re-export
// so the two never drift. Filename is the Next 15 file convention; there
// is no other way to set `twitter:image` from Metadata config without
// also setting an absolute URL by hand.
//
// `summary_large_image` is set in apps/web/app/layout.tsx:metadata.twitter
// so the 1200x630 card is rendered large rather than as a small thumbnail.

export { default, alt, size, contentType } from "./opengraph-image";
