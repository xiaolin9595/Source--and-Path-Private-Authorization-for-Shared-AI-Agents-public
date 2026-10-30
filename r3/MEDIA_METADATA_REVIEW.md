# Figure and PDF metadata review

The candidate contains one E3 PDF and lifecycle PDF/PNG/SVG renderings. PDF
inspection found no author, user properties, embedded JavaScript, attachments,
or custom metadata. Both PDFs identify only Matplotlib as creator/producer. The
lifecycle PDF/SVG retain a 2026-10-24 creation timestamp; this is experiment
provenance, not a person, account, host, or filesystem path. String scanning of
the PNG found no personal name, home path, workspace path, or account marker.

Recommendation: **the figures may remain enabled in the anonymous release**.
They contain no observed identity disclosure. Do not depend on the anonymous
web UI to preview PDF/SVG: verify availability and integrity through the
downloaded anonymous ZIP and its manifest. If the platform blocks inline PDF or
SVG rendering, keep the files downloadable and link the aggregate CSV plus
renderer; do not remove scientific assets merely to obtain a preview.
