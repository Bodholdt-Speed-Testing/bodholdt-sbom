# Changelog

All notable changes to this project are recorded here.

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
