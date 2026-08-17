# Changelog

All notable changes to this project are recorded here.

## 1.1.0

Closes all 22 high severity findings from the pre-publication review. See `KNOWN_ISSUES.md` for the
full list with reproductions; 26 medium and 5 low remain open.

**Stopped asserting things that were not true.**

- A file that merely mentions a package's CDN URL is no longer reported as being that package. The
  match is anchored to the real rewrite header inside the leading comment, and a mention anywhere
  else becomes a note. The preserved-banner branch is tested first, so a genuine banner can no
  longer be displaced by a CDN reference lower down the same file, which previously erased a real
  shipped jQuery from the report.
- Version inference is tiered and refuses to guess. A `const VERSION` beats a `define()`, which
  beats an `@version` docblock, and a docblock is trusted only in a file that looks like the
  library's entry point. Constants naming a schema, a database revision or a platform requirement
  are rejected. Two conflicting candidates produce no version and a note rather than a coin flip.
- A version read out of source code is always PARTIAL, and its evidence says "unverified". It used
  to be promoted to IDENTIFIED whenever a manifest supplied the name.
- LGPL and AGPL are no longer reported as GPL, and a LICENSE file naming more than one licence
  records none of them.
- `installed.json`'s own `dev-package-names` list is believed, instead of inferring dev scope from a
  hardcoded allowlist. In one real plugin this alone corrected 26 packages that were being asserted
  as shipped product.
- Components no longer carry a fabricated `"version": "unknown"`, SPDX identifiers are emitted as
  `license.id` rather than `license.name`, and scoped npm package URLs percent encode their `@`.

**Stopped being silent about things that were there.**

- Copied-in libraries are found without a LICENSE file or a manifest, and below the first directory
  level. Those two gates together meant the tool could not find most of what it exists to find.
  A manifest now raises confidence rather than granting entry, and foreignness needs positive
  evidence: code declaring names unrelated to the product. Code declaring nothing at all, such as a
  folder of templates, is not treated as foreign.
- Single-file libraries, prefixed vendor directories such as Strauss output, and packages nested
  inside another library are all reachable now.
- "Minified" is decided from content rather than from `.min.` in the filename, so a standard block
  build's `build/index.js` is no longer invisible. A source is looked for anywhere in the tree by
  stem, including `src/` layouts and Sass, so an author's own build output is not called third party.
- An unreadable directory becomes a note instead of an uncaught exception that killed the run.
- Running out of scan budget is reported as unknown rather than as "no PHP here", which used to
  delete whole packages from the report while the summary still claimed no gaps.
- The scanner's notes are carried into the CycloneDX document, so a consumer sees the caveats.

**Also fixed:** a non-string npm `license` no longer raises a PHP warning into stdout; PHP
diagnostics go to stderr so they cannot corrupt a redirected document; `json_encode` failure is
checked, so one non-UTF-8 byte no longer produced a one-byte file and exit 0; `--diff` validates its
input, reads `metadata.component` so a release comparison sees the product's own version change, and
recurses into nested components; glob metacharacters in a target path no longer silently disable
every detector.

Three further corrections came from testing the fixes against real plugins rather than fixtures:
CamelCase was not split during tokenisation, so `BodholdtGDrive_Licensing_Client` did not match the
product's own name and the author's own file read as third party; a pass-through directory was named
instead of the library inside it; and the wider net initially reported `admin/` and `assets/` as
dependencies, which is what produced the positive-evidence rule.

65 fixture tests, up from 38.

## 1.0.0

First release.

- Reports the third-party code inside a WordPress plugin or theme, sorted into identified,
  partially identified, not identified, and present but probably should not ship.
- Reads `composer.lock`, `vendor/composer/installed.json` and `package-lock.json`, separating
  build-time dependencies from the ones that actually ship.
- Finds libraries copied in wholesale with no manifest, identifying them from their own
  `composer.json`, then from a version constant in their source, then from their licence file.
  This is the case that lockfile-based tooling misses, and it is the reason the tool exists.
- Finds bundled JavaScript and CSS from CDN rewrite comments and preserved banners, and flags
  minified assets that have neither a banner nor a local source.
- Emits CycloneDX 1.6 JSON, with `bodholdt:confidence` and `bodholdt:evidence` on every component
  so a reader can see how each line was arrived at.
- Diffs two documents, to show what changed between releases.

Four defects were found and fixed by running the tool against real plugins before release, and
each one now has a regression test:

- A library's internal `lib/` directory was treated as a container of separate packages, which
  reported one large dependency as twenty six phantom components.
- An ordinary source comment mentioning a version was parsed as a preserved banner, inventing a
  component from `/* NEW in 10.15.0 */`.
- A `composer.lock` belonging to a dependency was read as though it described the product,
  mixing that dependency's private tree into the report and double counting.
- Component identity included the path, so the same package found by two detectors was reported
  twice.

A fifth was caught by CI, on PHP 7.4 only, which is the reason the version matrix exists:

- The main file carried a shebang. PHP 8 strips a shebang from an included file and PHP 7.4 does
  not, so including the tool emitted that line as output ahead of its `strict_types` declaration.
  That is fatal on 7.4, and on any version it would have put a stray line in front of JSON output.
  The shebang now lives only in `bin/bodholdt-sbom`, and the main file is run as
  `php bodholdt-sbom.php`.
