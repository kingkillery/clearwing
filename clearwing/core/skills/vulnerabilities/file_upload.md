# File Upload Vulnerabilities

File upload vulnerabilities occur when an application accepts user-supplied
files without adequately validating type, content, size, or storage
location — letting an attacker place attacker-controlled content where it
can be executed, served to other users, or used to abuse backend parsers.

This skill is intentionally payload-free: it describes attack *classes*
and defensive checks conceptually. Concrete exploit strings are left to
the engagement notes, both to keep this guidance durable and to avoid
tripping endpoint-protection signatures on the source tree.

## Risk categories to assess

### 1. Validation weaknesses

- **Extension allow/blocklists** — missing, case-sensitive-only, or
  blocklist-based checks that miss alternates (`.phtml`, `.phar`, `.shtml`,
  `.svg`, double extensions, trailing dots/spaces, Unicode confusables).
- **Content-Type / MIME checks** — the client-supplied `Content-Type`
  header is attacker-controlled; server-side sniffing of actual file
  bytes (magic numbers) is the only meaningful check.
- **Filename handling** — path traversal in the stored filename
  (`../../`), null bytes in legacy stacks, overwriting existing files,
  and OS-reserved names.

### 2. Execution-context weaknesses

- Uploaded files stored **inside the web root** with script handlers
  enabled — the classic upload-to-RCE path.
- Files served back **without** `Content-Disposition: attachment` and a
  safe `Content-Type`, enabling stored XSS via HTML/SVG uploads.
- Archive extraction (zip/tar) without entry validation — path traversal
  on extract ("zip slip"), symlinks, decompression bombs.

### 3. Parser-abuse surface

- Image/document processing libraries reached by uploads (resizers,
  thumbnailers, PDF/OLE parsers) — memory-safety CVEs triggered by
  crafted files. This is a prime fuzz target for native stacks.
- Polyglot files valid as two formats (e.g. image + script) that bypass
  sniffing but execute in another context.
- XML-bearing formats (SVG, Office docs) enabling XXE where parsed.

## Testing methodology (conceptual)

1. Map every upload endpoint, its storage location, and how uploaded
   files are later used (served, parsed, extracted, executed).
2. For each validation layer, test *boundary classes* rather than single
   cases: extension alternates, case variation, multi-extensions,
   mismatched Content-Type vs. real bytes, oversized inputs, nested
   archives, traversal sequences in filenames.
3. Verify the execution context: is the upload dir script-enabled? Is
   content served inline or as attachment? Which parsers touch the file?
4. Confirm defense-in-depth claims by trying the simplest instance of
   each class first, then escalating only as authorization allows.

## Defensive signals

- Uploads stored outside the web root on non-executable storage,
  served through a mediator that forces `Content-Disposition: attachment`.
- Server-side magic-byte validation plus per-type re-encoding (e.g.
  image re-rendering) that strips active content.
- Randomized stored filenames; original names kept as metadata only.
- Size limits and archive-ratio limits enforced before parsing.

## Remediation checklist

- [ ] Allowlist extensions **and** verify actual file bytes server-side
- [ ] Store uploads outside executable/web-served paths
- [ ] Force safe `Content-Type` + `Content-Disposition: attachment` on download
- [ ] Sanitize/randomize stored filenames; reject traversal sequences
- [ ] Validate archive entries before extraction; cap ratios and depth
- [ ] Keep parser libraries patched; sandbox or isolate heavy parsing
