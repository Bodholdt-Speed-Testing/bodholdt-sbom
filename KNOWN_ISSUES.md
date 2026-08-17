# Findings from the pre-publication review

**Review date:** 2026-08-17  
**Last updated:** 2026-08-17. **All 53 confirmed findings are resolved as of 1.2.0.**

## Status

| Severity | Count | Status |
|---|---|---|
| High | 22 | Fixed in 1.1.0 |
| Medium | 26 | Fixed in 1.2.0 |
| Low | 5 | Resolved by the two rounds above |
| **Total** | **53** | **All closed** |

A multi-agent adversarial review was run against 1.0.0. Five independent lenses examined the tool,
and every finding was handed to a separate agent briefed to refute it by reproducing it rather than
reasoning about it. **56 were raised, 53 survived that refutation, 3 were refuted.**

This file is kept because the reasoning is more useful than the list. Each entry keeps its original
reproduction, so a future change that reintroduces one is recognisable.

## The rule the whole review comes down to

Every finding here is a variation on one mistake: **claiming more than the evidence supports.** It
has two directions and the tool was going both ways at once.

**Asserting things that were not there.** A file mentioning a package's CDN URL was reported as
being that package, with a package URL emitted, and in the reproduced case that also erased a
genuinely shipped jQuery from the report. A schema revision was reported as a library's version. An
inferred version was filed under "name and version both known".

**Reporting silence as a clean bill of health.** A directory only counted if it kept a LICENSE file
or a manifest, and only one level down, so most copied-in code was reported in no category at all.
An exhausted scan budget rendered as "no PHP here". An unreadable directory killed the run.

The fixes are all the same shape. Tier the evidence, refuse to choose when two readings compete,
require positive evidence rather than absence of contrary evidence, and print what could not be
determined instead of omitting it.

## What each round changed

**1.1.0, the 22 high.** The CDN match is anchored to a real rewrite header inside the leading
comment and the banner branch runs first. Version inference is tiered, rejects schema and platform
constants, and records nothing when two candidates conflict. The LICENSE-or-manifest gate and the
depth limit are gone. Foreignness needs positive evidence. `installed.json`'s own `dev-package-names`
is believed. Unreadable directories, exhausted budgets and encoding failures are reported instead of
being fatal or silent.

**1.2.0, the 26 medium.** Banners are read from the whole leading comment block, so the multi-line
JSDoc shape and three-word product names are found. A same-directory minified twin is treated as
genuinely ambiguous and asked rather than assumed. The right plugin header becomes the subject when
several exist. A sub-package sharing the root vendor prefix is the author's own. A dev-tooling
package explicitly declared as a production requirement gets a question, not an accusation. Fonts
and WebAssembly are inventoried. Composer's own bookkeeping directory is not a package.

**Two regressions were introduced by the medium round and caught by running against real plugins
rather than fixtures:** the widened banner pattern picked up a banner on the author's own file, and
composer's internals directory became a component. Both now have tests. The lesson repeats: fixtures
confirm what you thought of, real code finds what you did not.

---



## High. Fixed in 1.1.0.

### 1. A CDN URL mentioned anywhere in a JS/CSS file is asserted as that file's identity, at the highest confidence level

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:652 (Scanner::identify_asset, jsDelivr branch)`

The jsDelivr regex is unanchored and runs against the first 4096 bytes of every .js/.css file, so any file that merely *mentions* a CDN URL is reported as being that package, with confidence IDENTIFIED and a purl — fabricating components that are not in the product at all.

**Reproduction.** Tree with the author's own `assets/admin.js` containing `var CHART_CDN = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';` (a lazy-loader) and `assets/docs.css` whose comment cites `.../npm/bootstrap@5.3.2/dist/css/bootstrap.min.css`. Output: `IDENTIFIED (2) — Name and version both known. These are the ones you can answer questions about.` listing `chart.js 4.4.0` at `assets/admin.js` and `bootstrap 5.3.2` at `assets/docs.css`, evidence `CDN banner in admin.js`. Neither library ships. `2 shipped components. 2 fully identified, 0 with gaps.` The same two fabricated entries, with purls, go into the CycloneDX document. Note the code comment at the *banner* branch (line 668) explains that anchoring and the `/*!` bang 'both matter... which is how this check failed the first time' — that hardening was never applied to this branch.

**Fix as proposed.** Anchor the CDN branch the same way the banner branch is anchored: require the match to be inside a leading comment at offset 0 (e.g. `^\s*/[/*][^\n]*\.../npm/...`), not anywhere in 4KB of arbitrary content.

### 2. Vendored libraries below the first directory level are never scanned, producing a clean bill of health for a plugin full of copied-in code

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:422 (Scanner::library_candidates)`

library_candidates() enumerates only `glob($this->root.'/*', GLOB_ONLYDIR)` plus composer-named vendor dirs, so anything one level further down — `includes/<lib>/`, `lib/<lib>/`, `inc/<lib>/`, the most common WordPress vendoring layouts — is never a candidate and is never reported in any category.

**Reproduction.** Plugin tree with three vendored libraries: `includes/acme-lib/` (own composer.json name+version+licence AND a LICENSE file), `includes/simple-html-dom/` (bare PHP), `lib/phpmailer/src/PHPMailer.php` (`const VERSION = '6.9.1'`) plus `lib/phpmailer/LICENSE`. Full output: `IDENTIFIED (0) None. / PARTIALLY IDENTIFIED (0) None. / NOT IDENTIFIED (0) None.` and `0 shipped components. 0 fully identified, 0 with gaps.` Because `$unknown === 0`, the 'The gaps are the useful output' paragraph is suppressed, so the report reads as an all-clear for a product shipping three third-party libraries.

**Fix as proposed.** Walk to a bounded depth (matching find_files()'s depth of 4) when collecting library candidates, or at minimum descend into the conventional WordPress container directories (`includes`, `inc`, `lib`, `libs`, `library`, `src`, `assets`) as candidate *bases* while still keeping the one-library-is-one-component rule.

### 3. A vendor/composer/installed.json blinds the tool to every other library in that vendor tree

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:285 (Scanner::detect_composer marks the whole vendor dir claimed) plus the Pass B guard at line 399`

detect_composer() pushes the entire `$vendor_dir` onto `$this->claimed` for every package it reads, and it runs before detect_vendored_php(). composer_style_vendor_dirs() then filters claimed paths out, and Pass B additionally skips any vendor dir that has `composer/installed.json`. Net effect: a library hand-copied into an existing `vendor/` is invisible — the single most likely place for unrecorded code to hide.

**Reproduction.** `vendor/composer/installed.json` listing only `psr/log 3.0.0`, plus a hand-copied `vendor/acme/hidden-lib/` carrying its own `composer.json` (`acme/hidden-lib 2.4.1 MIT`), a `LICENSE`, and `src/Thing.php`. Output: `IDENTIFIED (1) psr/log 3.0.0` and `1 shipped components. 1 fully identified, 0 with gaps.` — hidden-lib appears nowhere. Delete `vendor/composer/` from the identical tree and it is found immediately: `acme/hidden-lib 2.4.1 MIT ... vendored, identified from its own composer.json`.

**Fix as proposed.** Claim the individual package directories named in installed.json (`vendor/<name>`), not the vendor container, and let Pass B sweep whatever is left over in that vendor tree.

### 4. installed.json's own dev-package-names list is discarded; 24 dev-only packages are asserted to be shipped product components

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:283 (Scanner::detect_composer, scope assignment from installed.json)`

When reading `vendor/composer/installed.json` the tool ignores the file's `dev` flag and `dev-package-names` array — the authoritative record of which installed packages are dev-only — and instead assigns SHIPPED to everything except a hard-coded 13-name DEV_TOOLING list. The README says the code path from installed.json is 'a better answer than the lockfile'; it is in fact the only path where dev separation is thrown away.

**Reproduction.** `php bodholdt-sbom.php ./testbed-plugin-9` (real testbed). Its `vendor/composer/installed.json` has `"dev": true` and `dev-package-names` containing all 26 installed packages. Report: `IDENTIFIED (25)` listing `nikic/php-parser v5.7.0`, `theseer/tokenizer 1.3.1`, `phar-io/manifest`, `phpunit/php-code-coverage 10.1.16`, `sebastian/*` etc. under 'Name and version both known. These are the ones you can answer questions about.' Only `phpunit/phpunit` and `sebastian/diff` (the two that happen to be on the hard-coded list) reach 'PRESENT BUT PROBABLY SHOULD NOT SHIP'. Footer: `31 shipped components. 25 fully identified, 6 with gaps.` It also promotes `jQuery 3.6.1` and six `.min.js/.min.css` files out of `vendor/phpunit/php-code-coverage/src/Report/Html/Renderer/Template/` into the product's shipped inventory.

**Fix as proposed.** Read `dev-package-names` from installed.json and mark those packages DEV_ONLY (or SUSPICION), instead of relying on the 13-entry DEV_TOOLING constant. Also treat assets found under a dev-scoped package's own path as belonging to that package, not to the product.

### 5. The author's own minified build output is asserted to be unattributable third-party code with 'no local source'

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:683 (Scanner::identify_asset, minified branch)`

The 'has a local source' test is a same-directory, same-stem, same-extension sibling lookup (`is_file($m[1].'.'.$m[2])`). Sources kept in a `src/` subdirectory or written in Sass/Less fail it, so the tool prints 'Third party code is present here and this tool could not attribute it' and the evidence string 'minified asset with no banner and no local source' about files the author wrote. Separately, 'minified' is decided purely by the `.min.` filename, never by content.

**Reproduction.** (a) False positive: tree with `assets/js/src/admin.js` (hand-written source) → `assets/js/admin.min.js`, and `assets/css/admin.scss` → `assets/css/admin.min.css` — the standard WordPress layout. Output: `NOT IDENTIFIED (2)` listing both, evidence 'minified asset with no banner and no local source, origin unknown'; `2 shipped components. 0 fully identified, 2 with gaps.` (b) Both directions wrong at once: a hand-written, fully commented, unminified `assets/notreally.min.js` is flagged as a 'minified asset ... origin unknown', while a genuinely minified third-party bundle named `assets/bundle.js` (no banner, no `.min.`) is not reported at all.

**Fix as proposed.** Search for a plausible source anywhere in the tree by stem (including `src/`, `source/`, `.scss`/`.sass`/`.less` for CSS) before asserting 'no local source', and gate the word 'minified' on a content test (mean line length / newline density) rather than the filename.

### 6. Version inference reports unrelated *_VERSION constants and per-file @version docblocks as the library's version

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:514 (Scanner::find_version_constant)`

The three patterns match `define('<anything>VERSION', ...)` (case-insensitively, so minimum-platform constants match) and any `@version` docblock tag, in whichever file is reached first. The shallow-file pass is plain `glob()` order with no name scoring — the stem-matching sort is applied only inside lib/src/includes/source — so an `autoload.php`/`bootstrap.php` is read before the file actually named after the library. The wrong number is then printed as fact with the evidence 'version read from <file>'. For CRA reporting a wrong version is worse than no version.

**Reproduction.** (a) `acme-sdk/bootstrap.php` containing `define( 'ACME_MINIMUM_PHP_VERSION', '7.4' );` and `acme-sdk/src/AcmeSdk.php` containing `const VERSION = '3.11.0';`. Output: `acme-sdk  7.4 ... vendored, version read from acme-sdk/bootstrap.php`. The reported version is a minimum PHP requirement. (b) `acme-http/bootstrap.php` with a per-file docblock `@version 1.0.1` and `acme-http/src/Client.php` with `const VERSION = '7.9.2'`. Output: `acme-http  1.0.1 ... version read from acme-http/bootstrap.php` — the real library version is 7.9.2.

**Fix as proposed.** Reject defines whose constant name contains MIN/MINIMUM/REQUIRED/PHP/WP; apply the existing stem-scoring sort to the shallow pass too; prefer a `const VERSION` hit over an `@version` docblock hit rather than first-match-wins; and when two different candidate versions are found, report the component as PARTIAL with no version rather than picking one.

### 7. Non-string npm `license` field emits a PHP warning onto stdout, producing a file that is not JSON at all

**FIXED** · **Lens:** cyclonedx · **Location at time of review:** `bodholdt-sbom.php:356 (Scanner::detect_npm, lockfileVersion 2/3 branch) — `$c->licenses = isset( $pkg['license'] ) ? array( (string) $pkg['license'] ) : array();``

`(string)` is applied to a `license` value that npm legitimately writes as an array, which raises a PHP `Array to string conversion` warning; PHP CLI writes that warning to stdout, so it lands ahead of the JSON document, and the recorded licence becomes the literal string "Array".

**Reproduction.** Real, currently-installable dependency, no hand-editing: `npm init -y && npm i --package-lock-only eyes@0.1.8 pause-stream@0.0.11` writes `"license": ["MIT","Apache2"]` into package-lock.json v3 (verified against registry.npmjs.org). Add a plugin header and an empty node_modules dir, then run the documented stdout form: `php bodholdt-sbom.php ./realnpm --format=cyclonedx > sbom.json`. Exit code 0, "Written" semantics look fine, and sbom.json begins:

    \n
    Warning: Array to string conversion in .../bodholdt-sbom.php on line 356
    {
        "bomFormat": "CycloneDX",

Python `json.load` fails with `Expecting value: line 2 column 1`. With `--output=` instead, the file is syntactically valid but asserts `{"name":"pause-stream","version":"0.0.11","licenses":[{"license":{"name":"Array"}}]}` — a licence named "Array" attributed to somebody else's package.

**Fix as proposed.** Normalise the value before casting, the same way the composer branches do, and guard against non-scalars: `$raw = $pkg['license'] ?? array(); $c->licenses = array_values( array_filter( array_map( 'strval', array_filter( (array) $raw, 'is_scalar' ) ) ) );`. Separately, set `ini_set('display_errors','stderr')` (or `error_reporting` handling) at the top of the file so no PHP diagnostic can ever be interleaved into a document written to stdout.

### 8. json_encode failure is unchecked: a non-UTF-8 byte anywhere produces a 1-byte file, "Written to", and exit 0

**FIXED** · **Lens:** cyclonedx · **Location at time of review:** `bodholdt-sbom.php:848 (CycloneDX::render) — `return json_encode( $bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";``

`json_encode` returns `false` on malformed UTF-8; `false . "\n"` is the string "\n", so the tool silently emits an empty document, reports success on stderr, and exits 0. A build that runs this as its SBOM step believes it produced an SBOM.

**Reproduction.** Write a plugin whose header is ISO-8859-1 (routine for older EU-authored plugins): header line `Plugin Name: Björn Café Widget` encoded latin-1, `Version: 1.0.0`. Then `php bodholdt-sbom.php ./t1-latin1 --format=cyclonedx --output=sbom.json` prints `Written to sbom.json`, exits 0, and `sbom.json` is exactly 1 byte (`0a`). `json.load` fails with `Expecting value: line 2 column 1 (char 1)`. The text format renders the plugin fine, so nothing signals the failure. The same applies to any non-UTF-8 byte that reaches a component name, path or evidence string (e.g. a latin-1 asset filename on a Linux build host).

**Fix as proposed.** Capture the result and fail loudly: `$json = json_encode( $bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ); if ( false === $json ) { fwrite( STDERR, 'Could not encode document: ' . json_last_error_msg() . "\n" ); exit( 1 ); }`. Better, make it encodable at the source: run every captured name/path/evidence string through a UTF-8 check and transcode or replace, or add `JSON_INVALID_UTF8_SUBSTITUTE` and note the substitution in `notes`. `emit()` should also return non-zero when the payload is empty.

### 9. library_candidates() never descends below one level, so the dominant WP vendoring location (includes/, inc/, src/) is invisible

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:415-434 (library_candidates), line 420: glob( $base . '/*', GLOB_ONLYDIR )`

Pass A only globs one level below the root and below composer-style vendor dirs, so a wholesale-copied library sitting at includes/<lib>/ or includes/lib/<lib>/ is never even considered as a candidate, and stays silent rather than being reported as unidentified.

**Reproduction.** Identical library, two locations. tcpdf/ at root containing LICENSE + composer.json {"name":"tecnickcom/tcpdf","version":"6.6.2"} + tcpdf.php -> report says IDENTIFIED (1) tecnickcom/tcpdf 6.6.2. Move the same directory to includes/tcpdf/ with byte-identical contents -> IDENTIFIED (0), PARTIALLY IDENTIFIED (0), NOT IDENTIFIED (0), no NOTES. Same for lib/PHPMailer/ (composer.json + LICENSE + PHPMailer.php, which is where WP core itself puts PHPMailer) and includes/lib/stripe-php/ (LICENSE + composer.json + lib/Stripe.php with const VERSION = '13.10.0'): all report 0 shipped components.

**Fix as proposed.** Walk the tree for candidate directories to a bounded depth (3-4 is enough for real plugins) instead of globbing a single level, marking a directory as a candidate and then not descending into it. The existing is_claimed() subtree logic already prevents double-reporting once a candidate is accepted, so the depth restriction is not what is protecting against phantom components.

### 10. The LICENSE-or-composer.json gate makes the tool blind to precisely the undocumented vendoring it exists to find

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:428 — ( $this->has_license_file( $dir ) || is_file( $dir . '/composer.json' ) ) && $this->contains_php( $dir )`

A library copied in with its LICENSE and composer.json stripped — the single most common way third-party PHP arrives in a WordPress plugin, and the case the file header calls 'precisely the code nobody can account for' — is silently dropped, not reported as unidentified.

**Reproduction.** Root-level php-jwt/src/{JWT.php,Key.php} (namespace Firebase\JWT) and simple-html-dom/{simple_html_dom.php,node.php}, neither with LICENSE or composer.json -> IDENTIFIED (0) / PARTIAL (0) / NOT IDENTIFIED (0), no NOTES. Add a one-line LICENSE file to each and rerun the same tree -> simple-html-dom 1.9.1 appears under PARTIALLY IDENTIFIED and php-jwt appears under NOT IDENTIFIED. The presence of documentation is what makes the component visible, so the sloppier the vendoring the more complete the report claims to be. Also demonstrated with includes/tcpdf/ (tcpdf.php with const VERSION = '6.6.2' and @version 6.6.2) -> silent.

**Fix as proposed.** Treat 'directory containing PHP that is not the author's own namespace' as the candidate test and use LICENSE/composer.json only to raise confidence, not to gate entry. A cheap discriminator that does not produce phantom components: a directory whose PHP files declare a top-level namespace or class prefix that does not match the plugin's own, or whose files carry a copyright/@author differing from the plugin header. Failing that, emit it as UNIDENTIFIED — the design principle says an over-reported unknown is the cheap error and a silent miss is the expensive one.

### 11. Strauss/Mozart prefixed vendor trees produce zero components even though every package retains its composer.json and LICENSE

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:85 (VENDOR_DIRS) interacting with 415-434 (library_candidates) and 713-726 (composer_style_vendor_dirs)`

VENDOR_DIRS is a closed six-entry list (vendor, vendors, third-party, thirdparty, 3rdparty, external). Strauss's default output directory vendor-prefixed/ (and Mozart-style dependencies/, or any custom name) is not in it, so pass B never treats it as a multi-package container; and because its packages sit at depth 2 (vendor-prefixed/<publisher>/<package>) pass A cannot reach them either. Everything vanishes.

**Reproduction.** Plugin with vendor-prefixed/guzzlehttp/guzzle/{LICENSE,composer.json:{"name":"guzzlehttp/guzzle","license":"MIT"},src/Client.php}, vendor-prefixed/firebase/php-jwt/{LICENSE,composer.json,src/JWT.php}, strauss/psr/log/{LICENSE,LoggerInterface.php} -> IDENTIFIED (0), PARTIAL (0), NOT IDENTIFIED (0), no NOTES, '0 shipped components'. Namespace prefixing is now the standard way commercial WP plugins avoid collisions, and prefixed Guzzle/php-jwt remain vulnerable to the upstream CVEs under any namespace.

**Fix as proposed.** Two independent changes, either of which alone still leaves a hole: (a) recognise a directory as a multi-package container structurally — its children are two-level <publisher>/<package> dirs carrying composer.json or LICENSE — rather than by matching a fixed name list; (b) let pass A reach depth 2+ (see the depth finding). Additionally, a root composer.json containing an 'extra.strauss' or 'extra.mozart' key names the target directory explicitly and can be read directly.

### 12. Single-file vendored libraries are structurally excluded by GLOB_ONLYDIR, including files the tool already opens

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:420 — glob( $base . '/*', GLOB_ONLYDIR ) — candidates must be directories`

Every detector for copied-in PHP requires a directory, so the entire class of one-file drop-in libraries is silently missed, even when the file carries an explicit version the tool's own find_version_constant() patterns would have matched.

**Reproduction.** Plugin root containing Parsedown.php (const version = '1.7.4'), includes/Mobile_Detect.php (@version 2.8.39), includes/class-tgm-plugin-activation.php (@version 2.6.1) -> IDENTIFIED (0) / PARTIAL (0) / NOT IDENTIFIED (0), no NOTES, '0 shipped components'. Note read_plugin_header() at line 212 already file_get_contents() every root-level *.php, so Parsedown.php is literally opened and its version-bearing header read past. The README's 'does not detect code copied in file by file and mixed into your own source' disclaimer does not cover this: a discrete third-party file with its own class and its own version is not mixed into anyone's source.

**Fix as proposed.** Add a single-file pass: for each .php file not part of an already-claimed subtree, apply the same evidence chain (version constant, @version, @license/@package docblock tags, copyright line). Gate it on the file declaring a class/namespace whose name does not match the plugin's own prefix so the author's own files are not enumerated, and emit anything that survives as UNIDENTIFIED rather than guessing a name.

### 13. The claimed-subtree rule swallows nested vendor trees, so adding a LICENSE file removes real components from the SBOM

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:381-405 (detect_vendored_php pass A claims the whole subtree) interacting with 720 (composer_style_vendor_dirs filters out claimed paths)`

Pass A claims a library's entire subtree on the rationale that its subdirectories are namespaces. But a nested vendor/ directory inside that library holds genuinely separate third-party packages, and because pass B re-derives composer_style_vendor_dirs() after the claim it is filtered out — so those packages disappear. Detection gets strictly worse as the vendored tree gets better documented.

**Reproduction.** Tree: sdk/LICENSE, sdk/src/Sdk.php (const VERSION='4.2.0'), sdk/vendor/guzzlehttp/guzzle/{LICENSE,composer.json:6.5.5}, sdk/vendor/psr/http-message/composer.json:1.0.1 — no vendor/composer/installed.json (normal after a build prunes composer metadata). Result: PARTIALLY IDENTIFIED (1) sdk 4.2.0, and nothing else. Delete only sdk/LICENSE and rerun the byte-identical remainder: IDENTIFIED (2) guzzlehttp/guzzle 6.5.5 and psr/http-message 1.0.1. Guzzle 6.5.5 carries real published CVEs, and the documented tree is the one that hides it.

**Fix as proposed.** Do not claim a subtree past a nested vendor container. Either compute composer_style_vendor_dirs() once before pass A claims anything and scan those containers unconditionally, or make is_claimed() stop applying at any descendant directory whose name is a vendor container. Nesting a package inside a library is not the same relationship as a namespace subdirectory and the claim logic currently conflates them.

### 14. The minified-asset flag keys on the .min. filename rather than on content, so the default wp-scripts block build is invisible

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:676 — preg_match( '/^(.*)\.min\.(js|css)$/i', $file, $m )`

The only net for un-bannered bundled JS requires the filename to contain '.min.'. @wordpress/scripts — the officially recommended build tool for every block plugin — emits build/index.js: minified, no banner, no '.min.' in the name, and containing every inlined runtime npm dependency. It is passed over in silence.

**Reproduction.** Byte-identical 100KB minified blob written to two plugins. build/index.min.js -> NOT IDENTIFIED (1) 'minified asset with no banner and no local source, origin unknown'. build/index.js -> NOT IDENTIFIED (0), no NOTES. Same file, only the name differs. In the composite test the bundle also shipped with build/index.asset.php (<?php return array('dependencies' => array('react','wp-element','wp-i18n'), 'version' => 'a1b2c3');) and build/block.json beside it; grep confirms the tool contains zero references to 'asset.php', 'block.json' or 'package.json', so the two manifests sitting next to the bundle that name its dependencies and give it a build hash are never read.

**Fix as proposed.** Decide 'minified' from content, not the filename — e.g. mean line length over a threshold, or a very low newline-to-byte ratio — for any .js/.css under the tree. Separately, read *.asset.php next to a bundle: it yields the dependency list and a version hash for free, and a bundle whose companion manifest lists third-party deps should be emitted as UNIDENTIFIED with that list as evidence, since those packages are inlined into the shipped file.

### 15. CDN pattern matches any /npm/<pkg>@<ver> substring anywhere in the first 4 KB, and it runs before the banner check

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:652 (Scanner::identify_asset)`

The jsDelivr regex is unanchored and is not tied to the jsDelivr rewrite header, so any .js/.css file whose first 4096 bytes merely mention a CDN URL is reported as being that package, with confidence IDENTIFIED and a purl. Because the CDN branch is tested first, it also overrides a correct preserved banner sitting in position one.

**Reproduction.** /tmp/sbomfp/cdn2/assets/js/jquery-3.7.1.min.js starts with the conventional banner `/*! jQuery v3.7.1 | (c) OpenJS Foundation ...` and, three lines down, a comment mentioning `https://cdn.jsdelivr.net/npm/core-js-bundle@3.6.5/minified.js`. Output: `core-js-bundle 3.6.5 / IDENTIFIED / path assets/js/jquery-3.7.1.min.js / evidence "CDN banner in jquery-3.7.1.min.js"`. jQuery does not appear in the SBOM at all. Second repro at /tmp/sbomfp/cdn-ref: assets/js/admin.js contains only a TODO comment mentioning a sortablejs CDN URL, no sortablejs code ships, and the tool reports `sortablejs 1.15.0 IDENTIFIED, purl pkg:npm/sortablejs@1.15.0`. This is the worst class of output the tool can produce: a real package name, a precise version, an emitted purl, for code that is not in the product, while a package that IS in the product (jQuery, which carries CVE-2020-11022/11023) is suppressed.

**Fix as proposed.** Require the actual jsDelivr rewrite header shape rather than a bare substring: anchor to the start of the file and require the literal `Original file:` prefix that jsDelivr emits (`#^\s*/\*\*?.{0,400}?Original file:\s*/npm/((?:@[^/@]+/)?[^/@]+)@([0-9][^/\s]*)#s`), and run it only over the leading comment block. Everything else that merely mentions a CDN URL should be a NOTE ("this file references package X from a CDN"), not a component. Test the preserved-banner branch before the CDN branch so a first-position banner wins.

### 16. Version patterns pick up a version belonging to something other than the library, and attach it to a real package name

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:519 and :521 (Scanner::find_version_constant), :565 (version_search_order)`

The define() pattern matches any constant whose name merely ends in VERSION (schema versions, DB versions, minimum-requirement versions), and the @version pattern matches any docblock tag in any file. The shallow scan at line 565 emits `glob($dir.'/*.php')` in raw alphabetical order with none of the name-affinity sorting that is applied to lib/src/includes, so the first file alphabetically wins even when the correct version is in a sibling file.

**Reproduction.** (a) /tmp/sbomfp/wrongver/vendor/woocommerce/action-scheduler/action-scheduler.php contains `define( 'ACTION_SCHEDULER_STORE_SCHEMA_VERSION', '3' );` on the line before `define( 'ACTION_SCHEDULER_VERSION', '3.8.2' );`. Output: `woocommerce/action-scheduler  3  IDENTIFIED`. (b) /tmp/sbomfp/order/tcpdf/ contains barcodes.php (`@version 1.0.015`, the barcode sub-module) and tcpdf.php (`@version 6.6.5`, the library). Alphabetical order picks barcodes.php: output is `tcpdf  1.0.015  vendored, version read from tcpdf/barcodes.php`. A CVE matcher fed 'action-scheduler 3' or 'tcpdf 1.0.015' will either match nothing or match the wrong advisory set.

**Fix as proposed.** Restrict the define pattern to constants whose name is a plausible package-version constant, i.e. anchor on word boundary and reject known non-package suffixes: require the constant to match `^[A-Z0-9_]*_?VERSION$` AND not contain SCHEMA, DB, MIN, MINIMUM, REQUIRED, API, PROTOCOL, WP, PHP. Only accept `@version` when it appears in the file whose basename matches the directory stem, or in a file also containing `@package`. Apply the same name-affinity usort at line 565 that is applied to the lib/src/includes globs, and when two or more candidate versions are found in one directory, emit no version and a note instead of picking one.

### 17. An inferred version is promoted to IDENTIFIED whenever composer.json supplies a name

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:486-489 (Scanner::identify_vendored_library)`

Line 487 correctly sets PARTIAL with the comment "version by inference", then lines 488-489 overwrite it with IDENTIFIED merely because the name was confirmed. The version is still a guess, but the report files it under "Name and version both known. These are the ones you can answer questions about", removing the only signal that would tell the author to check it.

**Reproduction.** /tmp/sbomfp/wrongver/vendor/firebase/php-jwt has a real composer.json (`"name": "firebase/php-jwt"`, no version field, which is normal for Packagist packages) and src/JWT.php carrying a class docblock `@version 1.0.0`. Output: `firebase/php-jwt  1.0.0  IDENTIFIED  vendored, version read from vendor/firebase/php-jwt/src/JWT.php`. The real package is 6.x; 1.0.0 is a version this library never shipped, and the tool asserts full confidence in it. Same for woocommerce/action-scheduler version "3" in the same tree.

**Fix as proposed.** Delete lines 488-489. Confidence is the weaker of the name evidence and the version evidence: a name from composer.json plus a version by inference is PARTIAL, and the evidence string should say so ("name from composer.json, version inferred from <file>, unverified").

### 18. Licence sniffer reports LGPL as GPL and AGPL as GPL, and picks the wrong licence from a multi-licence file

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:592-626 (Scanner::sniff_license_file), map at :599-608`

The map is substring matching over the first 4096 bytes with no negative lookaround, so any text containing the phrase "GNU General Public License" is called GPL, and the first map entry to match wins regardless of which licence actually governs. LGPL and AGPL texts both quote the GPL by name in their opening sections, and a COPYING file that lists two licences is resolved by map order rather than by which licence covers the code.

**Reproduction.** Ran the tool over /tmp/sbomfp/licence with five authentic licence texts taken from this machine. ffmpeg's COPYING.LGPLv2.1 (LGPL-2.1) -> reported GPL-2.0 (matches "ordinary GNU General Public License." at line 67, then "version 2" from the title line "Version 2.1"). paramiko's LICENSE (LGPL-2.1) -> GPL-2.0. k6's LICENSE.md (AGPL-3.0) -> GPL-3.0 (matches "The GNU General Public License permits..." at line 41). libheif's COPYING (LGPL-3.0 library, MIT only for the sample apps) -> MIT, because 'mit license' is the first entry in the map and appears on line 2. Separately, a GPL-2.0-or-later text is reported flatly as "GPL-2.0" (/tmp/sbomfp/owncode). LGPL vs GPL decides whether copyleft propagates through linking, AGPL vs GPL decides whether network use triggers source disclosure, and calling an LGPL-3.0 library "MIT" tells a commercial plugin author a copyleft dependency is permissive.

**Fix as proposed.** Match on the licence title line, not on any substring: test for 'gnu lesser general public license' and 'gnu affero general public license' BEFORE 'gnu general public license', and require the GPL needle to be absent of a preceding 'lesser'/'affero' on the same line. Score all needles over the whole file and, when more than one distinct family matches, return null and add a note ("LICENSE names more than one licence, read it yourself") rather than picking the first. Detect the 'or (at your option) any later version' clause and emit the -or-later SPDX id.

### 19. vendor/composer/installed.json dev metadata is ignored, so dev-only packages are asserted to be part of the shipped product

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:269-287 (Scanner::detect_composer), scope set at :283`

installed.json carries `dev: true` and a `dev-package-names` array. The tool reads only the `packages` list and hard-assigns SHIPPED to every entry except the fourteen names hardcoded in DEV_TOOLING, so a vendor tree that is entirely dev dependencies is reported as the product's shipped bill of materials.

**Reproduction.** php bodholdt-sbom.php ./testbed-plugin-9. Its vendor/composer/installed.json has dev=true, 26 packages, and all 26 listed in dev-package-names. The tool reports "31 shipped components. 25 fully identified": 24 of the 26 dev packages (nikic/php-parser, phar-io/*, sebastian/*, theseer/tokenizer, myclabs/deep-copy, phpunit/php-code-coverage, ...) appear under IDENTIFIED in shipped scope, only phpunit/phpunit and sebastian/diff are flagged, and six more phantom entries (bootstrap.min.css, d3.min.js, nv.d3.min.js, popper.min.js, jQuery 3.6.1) are pulled out of php-code-coverage's HTML report templates and listed as shipped product code, with the six minified ones landing in NOT IDENTIFIED, the section the README calls "the list that matters".

**Fix as proposed.** Read `dev-package-names` from installed.json and set scope DEV_ONLY for every package in it (and treat `dev: true` at the top level as a signal that the tree was installed with dev deps). Stop relying on the DEV_TOOLING allowlist to infer dev scope from a manifest that states it explicitly. Also skip detect_bundled_assets for any path already claimed by a component whose scope is DEV_ONLY.

### 20. Any unreadable directory in the tree kills the whole run with an uncaught UnexpectedValueException

**FIXED** · **Lens:** robustness · **Location at time of review:** `bodholdt-sbom.php:777 (Scanner::walk), reached from detect_bundled_assets():633`

walk() constructs a RecursiveDirectoryIterator with no CATCH_GET_CHILD flag and no try/catch, so the first directory the process cannot open throws an uncaught UnexpectedValueException that aborts the entire scan.

**Reproduction.** mkdir -p /tmp/x/secret; printf '<?php\n/** Plugin Name: T1\n * Version: 1.0.0 */\n' > /tmp/x/plugin.php; echo x > /tmp/x/secret/inner.txt; chmod 000 /tmp/x/secret; php bodholdt-sbom.php /tmp/x  ->  'PHP Fatal error: Uncaught UnexpectedValueException: RecursiveDirectoryIterator::__construct(/tmp/x/secret): Failed to open directory: Permission denied ... on line 777', exit 255, no report at all. With --format=cyclonedx --output=sbom.json the output file is never created and the exit code is still 255. The same fatal fires at line 777 when the target directory itself is unreadable. Reproduced identically on macOS/PHP 8.5 and Linux/PHP 7.4.33 (running as nobody). Realistic triggers: scanning wp-content/plugins on a server as a non-root user, a CI job running as a different uid than the checkout, or a restricted ACL anywhere in the tree, including inside node_modules (which walk() does descend).

**Fix as proposed.** Pass \RecursiveIteratorIterator::CATCH_GET_CHILD as the third constructor argument and wrap the \RecursiveDirectoryIterator construction in a try/catch. On failure, record a note ('could not read <dir>, its contents are not in this report') rather than dying — an unreadable directory is exactly the 'code I could not account for' category the tool exists to surface, so it should become a line in the report, not a stack trace.

### 21. json_encode() failure is unchecked: one non-UTF-8 byte produces an empty CycloneDX document and exit 0

**FIXED** · **Lens:** robustness · **Location at time of review:** `bodholdt-sbom.php:848 (CycloneDX::render), consumed by emit():1175`

render() returns json_encode(...) . "\n" without testing for false, so when any component name, path or evidence string contains a byte that is not valid UTF-8 the function returns the single character "\n", which emit() happily writes to the output file and reports as success.

**Reproduction.** printf '<?php\n/**\n * Plugin Name: Caf\xe9 Manager\n * Version: 2.1.0\n */\n' > /tmp/y/cafe.php (an ISO-8859-1 plugin header, still common in older WordPress plugins); add any asset so the scan has content. Then: php bodholdt-sbom.php /tmp/y --format=cyclonedx --output=sbom.json  ->  prints 'Written to sbom.json', exit 0, and sbom.json is exactly 1 byte containing only a newline. To stdout it prints a blank line, exit 0. The text report for the same tree correctly lists jQuery 3.6.0, so the user has no signal that the machine-readable document they are about to file is empty. Confirmed on macOS/PHP 8.5 and Linux/PHP 7.4.33. On Linux the same failure is triggered by a filename rather than file contents: a minified asset named caf\xe9.min.js is listed under NOT IDENTIFIED in the text report but wipes the entire CycloneDX document (1-byte file, exit 0) — i.e. the tool's headline output silently disappears.

**Fix as proposed.** Capture the encode result, and on false write json_last_error_msg() to STDERR and return a non-zero exit code rather than emitting anything. Better still, sanitise on the way in (or encode with JSON_INVALID_UTF8_SUBSTITUTE) so a stray legacy-encoded byte degrades one field instead of destroying the document.

### 22. contains_php() reports 'no PHP here' after 200 files, silently deleting whole vendored packages from the SBOM

**FIXED** · **Lens:** robustness · **Location at time of review:** `bodholdt-sbom.php:735-746 (Scanner::contains_php), gating library_candidates():435 and detect_vendored_php():405`

contains_php() returns false when its 200-file budget runs out, so 'I gave up looking' is indistinguishable from 'there is no PHP in this directory'; the caller then drops the package entirely, with no note, and the summary still claims zero gaps.

**Reproduction.** Build vendor/acme/intl containing its own composer.json ({"name":"acme/intl","version":"7.0.1","license":"MIT"}), its own LICENSE, src/Intl.php, and a Resources/data directory of 600 .dat files. macOS/PHP 8.5: php bodholdt-sbom.php /tmp/sbomadv/t8-budget -> '0 shipped components. 0 fully identified, 0 with gaps.' The identical tree with 5 .dat files instead of 600 reports 'acme/intl 7.0.1'. Linux/PHP 7.4.33 with 3000 .dat files spread over 30 subdirectories: same result, '0 shipped components. 0 fully identified, 0 with gaps.', while `find` confirms the PHP file is present. Worse, the answer depends on filesystem readdir order: the 3000-file single-data-dir layout drops the package on APFS but keeps it on Linux overlayfs, so the same source tree yields two different bills of materials on two machines. Real packages in this shape are common (symfony/intl, giggsey/libphonenumber-for-php, anything shipping a large Resources/data or docs tree).

**Fix as proposed.** Distinguish 'budget exhausted' from 'nothing found'. Return a tri-state (or a bool plus an $exhausted flag) and, when the budget ran out, treat the directory as a candidate anyway and attach a note saying the check was truncated. A component the tool declined to examine must never be reported as '0 with gaps'.


## Medium. Fixed in 1.2.0.

### 23. Code copied in with no LICENSE and no manifest — the case the README says the tool exists for — is invisible

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:435 (Scanner::library_candidates gate: has_license_file || composer.json)`

A directory only becomes a candidate if it carries a LICENSE file or a composer.json. So the tool can only find copied-in code that the copier was careful enough to keep an attribution artifact for. The README's premise is the opposite: 'a great deal of third party code arrives in a plugin by being copied in, with no manifest, no version file, and nothing for a lockfile-based tool to read... the useful output is the list of things it found and could not identify.'

**Reproduction.** Top-level `simple-html-dom/simple_html_dom.php` and `acme-lib/src/AcmeLib.php`, both bare PHP, no LICENSE, no composer.json. Output: `NOT IDENTIFIED (0) None.` and `0 shipped components ... 0 with gaps.` Add a one-line `LICENSE` file to `simple-html-dom/` and rerun the identical tree: it now appears under `NOT IDENTIFIED (1)` with 'vendored directory containing PHP, not attributable to a known package'. The only difference between visible and invisible is whether the LICENSE file survived the copy.

**Fix as proposed.** Add a weaker structural signal for 'this directory is a library rather than my own code' — e.g. a top-level directory of PHP whose namespace/class prefix does not match the product's, or one that contains no reference to the product's text domain/prefix — and report those as UNIDENTIFIED. If that is judged too noisy to do reliably, say so explicitly in the README rather than letting the current gate read as full coverage.

### 24. The report tells the user to run --all, which the CLI rejects with exit 2

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:946 (TextReport::render) vs main() unknown-option branch at line 1126`

The BUILD TIME ONLY block prints 'Not part of the shipped product, listed for completeness. Use --all to expand.' No --all option exists; it is not in usage() and not in the README, and main() rejects any unrecognised `--` argument.

**Reproduction.** `php bodholdt-sbom.php ./testbed-plugin-5` prints `BUILD TIME ONLY (109) ... Use --all to expand.` Then `php bodholdt-sbom.php ./testbed-plugin-5 --all` prints `Unknown option: --all` and exits 2. The 109 build-time components are therefore not inspectable by any documented or undocumented means.

**Fix as proposed.** Either implement --all (add it to the option parser, usage(), and the README) or remove the sentence.

### 25. Components sharing a directory basename with no version collapse into one, silently shortening 'the list that matters'

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:71 (Component::key) used by Scanner::add at line 136`

The dedupe key is `strtolower(name).'@'.(version ?? '?')`. Unidentified components are named from a directory basename or a file basename and by definition have no version, so every unidentified component whose basename collides with another is dropped, and the printed count is short by the number dropped. The commented rationale ('Two detectors finding the same name and version have found one component') does not hold when the name is a filesystem basename and the version is literally unknown.

**Reproduction.** (a) `vendor/alpha/utils/u.php` and `vendor/beta/utils/u.php`, two distinct unattributable libraries. Output: `NOT IDENTIFIED (1)` — a single `utils` entry at `vendor/alpha/utils`. (b) `assets/vendor-a/bundle.min.js` and `assets/vendor-b/bundle.min.js`, two different vendor bundles. Output: `NOT IDENTIFIED (1)` — one `bundle.min.js` at `assets/vendor-b`; `1 shipped components ... 1 with gaps.`

**Fix as proposed.** Include the path in the key whenever confidence is UNIDENTIFIED (or whenever version is null), so unattributable findings are never merged. Merging is only safe once a package identity is actually established.

### 26. The IDENTIFIED / PARTIAL buckets do not match their own printed definitions, and the README's sample output shows a section the tool never produces

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:926 and 932 (TextReport section blurbs); confidence is set from version alone at lines 211, 279, 310, 479-490; README.md:33-34 and 86-96`

Confidence is computed as `$c->version ? IDENTIFIED : PARTIAL` everywhere — licence is never considered. So (a) a component with a version but no licence lands under 'IDENTIFIED — Name and version both known. These are the ones you can answer questions about', contradicting the README's 'Partially identified. Found and named, but the version **or the licence** is missing'; and (b) vendored libraries with both a version and a licence land under PARTIAL, printed beneath a blurb stating that one of the two is missing. The README's 'What the output looks like' block compounds this by showing stripe-php under `NOT IDENTIFIED (1)`, a section the tool never puts it in.

**Reproduction.** (a) `php bodholdt-sbom.php ./testbed-plugin-7` → `IDENTIFIED (1) canvas-confetti 1.5.1 / (no licence found)`. A licence gap is filed under 'you can answer questions about'. (b) `php bodholdt-sbom.php ./testbed-plugin-6` → `PARTIALLY IDENTIFIED (1) stripe-php 19.0.0 / MIT / vendored, version read from stripe-php/lib/Stripe.php` under the blurb 'Found and named, but the version or the licence is missing' — nothing is missing. README.md:87 shows this exact component under `NOT IDENTIFIED (1)` with the 'could not attribute it' blurb.

**Fix as proposed.** Demote to PARTIAL when licences are empty as well as when version is null, so the printed definition is true; give PARTIAL a second blurb (or a per-row reason) covering 'version inferred rather than declared'; and correct the README sample to the section the tool actually prints.

### 27. npm build-time/shipped separation is discarded exactly when the tool is used as instructed

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:338 (Scanner::detect_npm, $ships) and 358/369 (scope assignment)`

README: 'package-lock.json, with build time dependencies separated from shipped ones.' The lockfile records that separation itself in each entry's `dev` flag, but the code overrides it with `$ships = is_dir(.../node_modules)`: if node_modules is absent, every entry — including declared runtime dependencies — becomes DEV_ONLY. The README also tells the user to run the tool on staged build output just before zipping, which never contains node_modules. So under the recommended usage the advertised separation never actually happens.

**Reproduction.** Tree with `assets/app.bundle.js` and a lockfileVersion-3 `package-lock.json` declaring `lodash` and `@sentry/browser` as dependencies and `vite` as a devDependency. Without node_modules: `BUILD TIME ONLY (3)` and `0 shipped components. 0 fully identified, 0 with gaps.` — all three, including the two runtime deps, relabelled build-time. `mkdir node_modules/lodash` and rerun the identical lockfile: `IDENTIFIED (2) @sentry/browser 7.120.0, lodash 4.17.21` shipped, `BUILD TIME ONLY (1)`. Same data, opposite answers, decided by an empty directory.

**Fix as proposed.** Honour the lockfile's `dev` flags for classification regardless of node_modules, and use the absence of node_modules only to raise the existing note about inlined bundles — not to override the lockfile's own record.

### 28. The CycloneDX document omits every note the tool raised, including its own coverage caveats

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:812 (CycloneDX::render — $result['notes'] is never read)`

README: 'If you pass this document to somebody else, they can see how each line was arrived at.' The per-component evidence properties are emitted, but the scanner's notes — 'node_modules is not present, so they are treated as build time only... this tool cannot see that', 'A .git directory is present', 'Could not parse <file>: <json error>' — are dropped. The machine-readable artifact is strictly less honest than the text report, and it is the artifact that gets handed on.

**Reproduction.** Same t-npm tree as above. Text output contains the node_modules note. `php bodholdt-sbom.php <dir> --format=cyclonedx | grep -ci 'node_modules|note'` returns 0. A recipient of the JSON has no way to learn that all npm dependencies were classified by a directory-existence guess, or that a manifest failed to parse.

**Fix as proposed.** Emit the notes into the BOM — e.g. `metadata.properties` entries named `bodholdt:note`, or a CycloneDX `annotations` block — so the caveats travel with the document.

### 29. The node_modules hygiene note only fires at the top level, so 'it will say so' is untrue for the common layouts

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:701-706 (Scanner::detect_shipping_hygiene)`

README: 'If it sees a .git directory or a node_modules directory it will say so.' Both checks are `is_dir($this->root.'/<name>')` — root only. A node_modules under a build subdirectory (or a .git in a nested package) produces no note, while find_files() and detect_bundled_assets() both deliberately skip node_modules, so nothing else surfaces it either.

**Reproduction.** Tree containing `build/node_modules/left-pad/package.json` and a plugin header. Output has no NOTES section at all and reports `0 shipped components. 0 fully identified, 0 with gaps.` Adding a top-level `.git` to the same tree produces only the .git note; the nested node_modules is still never mentioned.

**Fix as proposed.** Detect `node_modules` and `.git` anywhere within the bounded walk, not just at the root, and name the path in the note.

### 30. `licenses` is serialised as a JSON object instead of an array — a hard CycloneDX 1.6 schema violation

**FIXED** · **Lens:** cyclonedx · **Location at time of review:** `bodholdt-sbom.php:864 (CycloneDX::component) fed by :278, :309 and :477 — `array_map( 'strval', (array) ( $composer['license'] ?? array() ) )``

When a `license` value decodes to a string-keyed array, the `(array)` cast and both `array_map` calls preserve those keys, so `json_encode` emits `licenses` as an object. CycloneDX 1.6 defines `component.licenses` as `licenseChoice`, `"type": "array"`. The same code also promotes the URL half of the value into a fabricated licence name.

**Reproduction.** A vendored library at `vendor/acme/widget/composer.json` with `{"name":"acme/widget","version":"1.4.2","license":{"type":"MIT","url":"https://example.com/mit"}}` produces:

    "licenses": {"type":{"license":{"name":"MIT"}},"url":{"license":{"name":"https://example.com/mit"}}}

Validated against the official bom-1.6.schema.json (Draft-7, spdx/jsf subschemas resolved): 2 errors — `components/0/licenses -> ... is not of type 'array'` and `... is not valid under any of the given schemas`. All eight real-plugin documents from the testbed validate with 0 errors, so this is the only path that breaks the schema outright.

**Fix as proposed.** Wrap every licence list in `array_values()` and drop non-string members: at :278, :309 and :477 use `array_values( array_map( 'strval', array_filter( (array) ( ... ?? array() ), 'is_scalar' ) ) )`, and wrap the `array_map` at :864 in `array_values()` as a belt-and-braces guard.

### 31. npm workspace lockfile paths are turned into purls for npm packages that do not exist

**FIXED** · **Lens:** cyclonedx · **Location at time of review:** `bodholdt-sbom.php:353-360 (Scanner::detect_npm) — `$name = $pkg['name'] ?? preg_replace( '#^.*node_modules/#', '', (string) $rel_path ); ... $c->purl = 'pkg:npm/' . $name . '@' . $c->version;``

For lockfileVersion 2/3 the `packages` map is keyed by workspace-relative path, not only by `node_modules/...`. When the key has no `node_modules/` prefix the regex leaves the path intact and it is pasted straight into a purl, so a directory path becomes a scoped-package identity assertion. Local workspace packages — the author's own code — are also reported as shipped third-party libraries pointing at the public registry.

**Reproduction.** package-lock.json v3 with `"packages": { "": {...}, "packages/ui": {"name":"@acme/ui","version":"1.2.3"}, "apps/admin": {"version":"0.1.0"}, "node_modules/@acme/ui": {"resolved":"packages/ui","link":true}, "node_modules/lodash": {"version":"4.17.21"} }` yields:

    @acme/ui    1.2.3    pkg:npm/@acme/ui@1.2.3
    apps/admin  0.1.0    pkg:npm/apps/admin@0.1.0
    @acme/ui    unknown  null
    lodash      4.17.21  pkg:npm/lodash@4.17.21

`pkg:npm/apps/admin@0.1.0` parses as scope `@apps`, name `admin` — an assertion that the product contains a public npm package that is really a local directory, and that anyone can register. The `link: true` entry also duplicates `@acme/ui` at version "unknown".

**Fix as proposed.** Only treat a `packages` key as a dependency when it contains `node_modules/`; skip `link: true` entries entirely. Something like: `if ( false === strpos( (string) $rel_path, 'node_modules/' ) || ! empty( $pkg['link'] ) ) { continue; }`, and derive the name only from the substring after the final `node_modules/`. Workspace-local packages belong in `notes`, not in `components`.

### 32. Scoped npm purls are not percent-encoded, so they are not canonical package-urls

**FIXED** · **Lens:** cyclonedx · **Location at time of review:** `bodholdt-sbom.php:360, :371 and :656 — `'pkg:npm/' . $name . '@' . $c->version``

The npm purl type definition states the scope's `@` prefix "is always percent encoded" (canonical example `pkg:npm/%40angular/animation@12.3.1`), and CycloneDX 1.6 says of `purl`: "The purl, if specified, must be valid and conform to the specification". The tool emits the raw `@`, so every scoped package carries a non-canonical identity.

**Reproduction.** `php bodholdt-sbom.php .../testbed-plugin-5 --format=cyclonedx` emits 79 purls of the form `pkg:npm/@babel/code-frame@7.29.0`; testbed-plugin-11 emits 133 more. Round-tripping the document through cyclonedx-python-lib (`Bom.from_json` then `JsonV1Dot6`) rewrites every one of them to `pkg:npm/%40babel/code-frame@7.29.0` — the two purl sets compare unequal. packageurl-python's `to_string()` canonicalises identically. Any consumer that compares, merges or de-duplicates purls by string will treat the tool's document and a mainstream generator's document as describing different packages.

**Fix as proposed.** Percent-encode the scope when building the purl: split a leading `@scope/name` and emit `'pkg:npm/' . rawurlencode( '@' . $scope ) . '/' . $name . '@' . $version`, i.e. `%40scope`. Consider also filling CycloneDX `group`/`name` (`"group": "@babel", "name": "core"`) rather than putting the whole scoped name in `name`, which is what consumers expect for npm.

### 33. `"version": "unknown"` fabricates a version in a field CycloneDX 1.6 makes optional

**FIXED** · **Lens:** cyclonedx · **Location at time of review:** `bodholdt-sbom.php:855 (CycloneDX::component) — `'version' => $c->version ?? 'unknown',``

CycloneDX 1.6 requires only `type` and `name` on a component (`definitions.component.required == ["type","name"]`), and defines `version` as "A single disjunctive version identifier". Writing the literal string "unknown" asserts a version that does not exist, instead of omitting the field. The tool's central signal — that it could not identify this thing — survives only in the non-standard `bodholdt:confidence` property, which most consumers discard, while the standard field makes a positive claim.

**Reproduction.** `php bodholdt-sbom.php .../testbed-plugin-9 --format=cyclonedx` emits 6 components with `"version": "unknown"`, e.g. `{"name":"bootstrap.min.css","version":"unknown","type":"library","purl":null}`. A consumer reading that document sees a library whose version is the string "unknown", indistinguishable from a real version identifier, and it can never match an advisory range. The same string is then propagated by the tool's own `--diff` (line 1056, `(string) ( $c['version'] ?? 'unknown' )`).

**Fix as proposed.** Omit the key when the version is unknown: build the array as `$out = array( 'type' => $c->type, 'name' => $c->name ); if ( null !== $c->version && '' !== $c->version ) { $out['version'] = $c->version; }`. The absence of `version` is the spec's way of saying exactly what the tool wants to say.

### 34. `--diff` keys CycloneDX documents on bare `name`, ignores nested components, and ignores metadata.component

**FIXED** · **Lens:** cyclonedx · **Location at time of review:** `bodholdt-sbom.php:1047-1059 (Diff::load) — `foreach ( (array) ( $data['components'] ?? array() ) as $c ) { $out[ (string) $c['name'] ] = ... }``

CycloneDX identity is `purl`/`bom-ref`, or at minimum `group` + `name` + `version`; `name` alone is not unique, `components` may nest (`component.components`), and the subject of the BOM lives in `metadata.component`, not in `components`. Diff::load reads none of that, so a real dependency upgrade is reported as no change at all.

**Reproduction.** Three separate demonstrations, all on documents that validate cleanly against bom-1.6.schema.json (0 errors):
(a) Two docs whose only difference is `{group:"@babel", name:"core"}` moving 7.20.0 -> 7.26.0, alongside `{group:"@types", name:"core", version:"1.0.0"}`. The second entry overwrites the first in the name-keyed map, both maps collapse to `{core: 1.0.0}`, and the tool prints "No component changes. / 0 changed, 0 added, 0 removed."
(b) A nested `components[0].components[0]` moving 9.9.9 -> 10.0.0: "No component changes."
(c) Two SBOMs the tool generated itself from the same plugin at Version 1.4.0 and Version 2.0.0 (`metadata.component.version` 1.4.0 vs 2.0.0): "No component changes." The product's own version bump is invisible in the release diff.

**Fix as proposed.** Key on identity, not name: prefer `purl`, fall back to `bom-ref`, then to `trim(($c['group'] ?? '') . '/' . $c['name'], '/')`. Walk nested `components` recursively. Include `metadata.component` as a row so the subject's own version change is reported (or print it explicitly in the header alongside the filenames).

### 35. The preserved-banner regex misses the multi-line and three-word banner shapes that most real dist files actually use

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:661 — '#^\s*/\*!\s*([A-Za-z][A-Za-z0-9._\-]{1,30}(?:[ ][A-Za-z0-9._\-]{1,20})?)[\s,|]+v?([0-9]+\.[0-9]+...#'`

Two independent limits in one pattern: the name may be at most two space-separated words, and the name must follow /*! with only whitespace between — a leading ' * ' on the next line breaks it. That excludes the standard multi-line JSDoc-style banner and any three-word product name, which together cover most real vendored dist headers. README explicitly claims banner detection.

**Reproduction.** Four files in one plugin, none named .min: '/*! jQuery v3.6.0 | (c) ... */' -> IDENTIFIED jQuery 3.6.0. '/*! Chart.js v4.4.1 */' -> IDENTIFIED Chart.js 4.4.1. Bootstrap's actual banner, '/*!\n  * Bootstrap v5.3.3 (https://getbootstrap.com/)\n  * Licensed under MIT\n  */' -> silent. Font Awesome's actual banner, '/*! Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com */' -> silent. Also silent: moment.js's '//! version : 2.29.4' form, lodash's '/**\n * @license\n * Lodash <https://lodash.com/>' form, and '/*!\n * jQuery Validation Plugin v1.19.5' (three words).

**Fix as proposed.** Match on the banner block rather than the first token: take the first comment block (/*! … */, /** … */, or a run of leading //! lines), strip leading '*' and whitespace from each line, then search the block for a name-then-version pair. Keep the BANNER_STOPWORDS guard and keep requiring the block to be the first thing in the file, since those are what prevented the 'NEW in 10.15.0' false positive — neither of them requires the current single-line, two-word shape.

### 36. The unminified-sibling rule suppresses detection for exactly the vendored dist folder it is meant to distinguish from

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:676-679 — if ( is_file( $m[1] . '.' . $m[2] ) ) return null; // Built from a local source`

'An unminified source of the same name sits beside it' is treated as proof the file is the author's own build output. Every third-party dist folder downloaded from a release page or a CDN ships both foo.js and foo.min.js side by side, so the heuristic fires hardest on genuinely third-party code and the pair becomes doubly invisible: the .min file is suppressed, and the unminified file is only ever checked for a banner.

**Reproduction.** assets/vendor/select2/select2.min.js alone (un-bannered) -> NOT IDENTIFIED (1) 'minified asset with no banner and no local source'. Copy select2.js in beside it — nothing else changed — and rerun: NOT IDENTIFIED (0), no NOTES. Same with assets/vendor/bootstrap/css/{bootstrap.css,bootstrap.min.css} carrying Bootstrap's real multi-line banner: both files silent.

**Fix as proposed.** An author's own build output normally has its source in a separate tree (src/, assets/src/, resources/) and its unminified twin is usually absent from the shipped zip, whereas a vendor dist has both files in the same directory. Require the unminified source to live outside the minified file's own directory before treating the pair as author-built; when both sit in the same directory, that is evidence of a vendored dist and should raise the pair, not suppress it.

### 37. contains_php()'s 200-file budget returns false on exhaustion, so large asset-heavy libraries are dropped and results depend on filesystem order

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:728-739 — $budget = 200; ... if ( $budget-- <= 0 ) { return false; }`

Running out of budget is reported as 'contains no PHP' rather than 'unknown', so a fully manifested library whose PHP files happen to be iterated after 200 non-PHP files is silently excluded from both pass A and pass B. The failure mode scales the wrong way: the bigger the vendored library, the more likely it disappears. It is also walk-order dependent, so the same tree can produce different SBOMs on different filesystems.

**Reproduction.** tcpdf/ at root with LICENSE, composer.json {"name":"tecnickcom/tcpdf","version":"6.6.2"}, src/tcpdf.php, and fonts/ holding 260 non-PHP files (TCPDF genuinely ships hundreds of font metric files) -> IDENTIFIED (0), PARTIAL (0), NOT IDENTIFIED (0), no NOTES. Trim fonts/ to 10 files, change nothing else -> IDENTIFIED (1) tecnickcom/tcpdf 6.6.2.

**Fix as proposed.** On budget exhaustion return true (or a third 'unknown' state that still admits the candidate) rather than false — an unresolved large directory should fall through to UNIDENTIFIED, not vanish. Better still, when the directory already has a composer.json or LICENSE, skip the contains_php() test entirely; the manifest is stronger evidence than a file-extension scan, and the check is only there to avoid phantom components in directories with no evidence at all.

### 38. A node_modules tree that actually ships yields no components and no note unless it sits exactly at the root, and no shipped artifact outside .js/.css is ever considered

**FIXED** · **Lens:** false-negatives · **Location at time of review:** `bodholdt-sbom.php:695 (root-only is_dir check), 630 (asset walk skips /node_modules/), 627 (only .js and .css), 422 and 757 (node_modules excluded from candidates and from find_files)`

node_modules is excluded from every detector by name, and the compensating hygiene note only fires for a root-level node_modules. A node_modules one level down that genuinely ships produces neither components nor a note, even though each package's own package.json on disk carries name, version and licence. Separately, detect_bundled_assets() filters to .js|.css only, so shipped webfonts, .wasm modules and platform binaries are not components and draw no note either.

**Reproduction.** Plugin with blocks/node_modules/lodash/package.json {"name":"lodash","version":"4.17.21","license":"MIT"} + lodash.js, blocks/node_modules/dompurify/package.json {"name":"dompurify","version":"2.0.7","license":"MPL-2.0"} + purify.js, assets/fonts/{fa-solid-900.woff,Roboto-Regular.ttf,inter-v13-latin-regular.woff2,OFL.txt}, assets/wasm/pdfium.wasm, bin/cwebp (Mach-O, +x) -> 'Scanned: 11 files', IDENTIFIED (0), PARTIAL (0), NOT IDENTIFIED (0), and no NOTES section at all. DOMPurify 2.0.7 has published XSS advisories and is fully self-identified on disk. Note the tool never reads any package.json anywhere: grep for 'package.json' in the source returns only comment text and lockfile-path filters.

**Fix as proposed.** Two cheap changes. (1) Make the shipping-hygiene node_modules check recursive, and when one is present read each package.json under it for name/version/license — the metadata is already on disk and gives IDENTIFIED components rather than a note. (2) Widen the asset walk to inventory shipped non-source artifacts (font formats, .wasm, executables) as UNIDENTIFIED entries rather than filtering to .js|.css; naming an unattributed .woff2 or .wasm is exactly the output the tool says it exists to produce, and font licences carry redistribution obligations of their own.

### 39. Banner stopword list is bypassed by the optional second word, fabricating components from ordinary comments

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:668-678 (banner branch), stopword list at :106-109`

The stopword test at line 670 is applied to the whole captured string, but the capture may be two words. 'fixed' and 'updated' are stopwords; 'Fixed in' and 'Updated for' are not. The second word also happily captures a bare hyphen, mangling real library names. And a build tool's own banner on the author's own asset is reported as a separate third-party component.

**Reproduction.** /tmp/sbomfp/banner produces four IDENTIFIED components from four ordinary CSS comments: `Fixed in 2.4.1` (from `/*! Fixed in 2.4.1 - stacking context bug on the settings screen */`), `Updated for 6.4`, `Generated 1.0.0`, and `elementor -  3.16.0` (from the real-world Elementor banner form `/*! elementor - v3.16.0 - 20-08-2023 */`, where the optional group swallows the dash and yields the unresolvable name "elementor -"). Separately /tmp/sbomfp/banner2: a webpack/terser banner `/*! Acme Forms v3.2.0 | (c) 2026 Acme | GPL-2.0-or-later */` on the plugin's own app.min.js is reported as the third-party component `Acme Forms 3.2.0`.

**Fix as proposed.** Apply the stopword test to each captured word, not the joined string, and expand the list with the changelog and build vocabulary (generated, compiled, built, release, minified, copyright, custom, core, reset, base, main). Reject a capture whose second word is punctuation-only by tightening the optional group to `[ ][A-Za-z][A-Za-z0-9._\-]{0,19}`, and strip a trailing separator before naming. Suppress the component when the captured name case-insensitively matches the root component's name or the directory basename.

### 40. The subject of the whole SBOM is taken from whichever root .php file glob returns first, with no warning when several carry a plugin header

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:218-236 (Scanner::read_plugin_header)`

read_plugin_header returns on the first match and never checks whether another root file also declares a Plugin Name. glob() is alphabetical, and '-' (0x2D) sorts before '.' (0x2E), so any `<slug>-legacy.php`, `<slug>-loader.php`, `<slug>-deprecated.php` beats `<slug>.php`. The result becomes CycloneDX metadata.component, the identity the entire document is about.

**Reproduction.** /tmp/sbomfp/subject contains acme-forms.php (Plugin Name: Acme Forms, Version: 3.2.0) and acme-forms-legacy.php (Plugin Name: Acme Forms (legacy compatibility shim), Version: 1.9.0). `--format=cyclonedx` emits metadata.component = {"name": "Acme Forms (legacy compatibility shim)", "version": "1.9.0"}. No note is raised. An SBOM filed under a CRA obligation would name the wrong product at the wrong version.

**Fix as proposed.** Collect every root .php file carrying a Plugin Name header. If more than one, pick the one whose basename matches the directory name (falling back to the largest file), and always emit a note listing the rejected candidates and the header each declared.

### 41. should-not-ship flag fires on general-purpose libraries declared as production dependencies

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:283 and :316, list at :97-103 (DEV_TOOLING)`

DEV_TOOLING is matched by exact package name with no regard for how the package was required. sebastian/diff is a standalone BSD-3 diff library with legitimate runtime uses (and squizlabs/php_codesniffer is legitimately shipped by code-quality plugins). When such a package appears in composer.lock's production `packages` section, the tool still asserts it should not ship and instructs the author to remove it.

**Reproduction.** /tmp/sbomfp/devflag/composer.lock declares sebastian/diff 5.1.1 under `packages` (production) and an empty `packages-dev`. Output: section 'PRESENT BUT PROBABLY SHOULD NOT SHIP (1)' listing sebastian/diff, plus the note "Test or build tooling found in shipped scope: sebastian/diff. Confirm it is excluded from your release build." Following that instruction breaks a plugin that genuinely requires it.

**Fix as proposed.** Only raise SUSPICION when the package is in DEV_TOOLING AND the manifest does not declare it as a production requirement. When composer.lock lists it under `packages`, downgrade to a note ("sebastian/diff is usually a test dependency; it is declared as a production requirement here, confirm that is intended"). Remove sebastian/diff and squizlabs/php_codesniffer from the unconditional list, or gate them behind the presence of a sibling test-only package.

### 42. CDN version capture swallows trailing punctuation, emitting a malformed version and an invalid purl

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:652-658`

The version group is `([0-9][^/\s]*)`, which excludes only slash and whitespace, so quotes, semicolons, parentheses and backticks are captured as part of the version whenever the URL is not followed by a path segment. The corrupted string is written straight into both the version field and the purl.

**Reproduction.** /tmp/sbomfp/cdn-ref/assets/js/lazy.js contains `s.src = "https://cdn.jsdelivr.net/npm/chart.js@4.4.0";`. Text report: `chart.js  4.4.0";`. CycloneDX: {"name":"chart.js","version":"4.4.0\";","purl":"pkg:npm/chart.js@4.4.0\";"}. That purl is not a valid Package URL and will either fail to parse or silently fail to match in any downstream vulnerability tool.

**Fix as proposed.** Constrain the version group to the characters a semver-ish version can contain: `([0-9][0-9A-Za-z.+-]*)`, and validate the result against `^[0-9][0-9A-Za-z.+-]*$` before setting purl. Percent-encode or refuse to emit a purl for anything that fails.

### 43. Components are keyed by name@version, so two distinct unidentifiable artifacts collapse into one entry with one path

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:71-73 (Component::key) and :136-156 (Scanner::add)`

Unidentified components are named by basename and have no version, so their key is `<basename>@?`. Two genuinely different files or directories that share a basename produce the same key and the second is discarded. The surviving record asserts a single path, which is a wrong statement about where that code lives, and the discarded one vanishes from the section the README calls the valuable output.

**Reproduction.** /tmp/sbomfp/collide contains two different bundles, assets/admin/bundle.min.js and assets/public/bundle.min.js, and two different vendored packages, vendor/acme/logger and vendor/other/logger. Output lists exactly one `bundle.min.js` with path `assets/admin/bundle.min.js` (the public one is gone) and one `logger`. Summary says "3 shipped components" where four distinct artifacts exist.

**Fix as proposed.** Include the path in the key for any component whose confidence is UNIDENTIFIED or whose version is null (`strtolower($name).'@'.($version ?? '?').'#'.$path`). Keep the name-only key only for records that have both a name and a version, where merging is genuinely the same package.

### 44. npm workspace link entries are reported as a second, versionless copy of a package that is already fully identified

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:347-362 (Scanner::detect_npm)`

lockfileVersion 2/3 `packages` entries include `"link": true` aliases that point at a workspace directory. They carry no name and no version, so the tool derives a name from the path and files them as PARTIAL, fabricating a gap for a package it has already identified from the workspace entry.

**Reproduction.** /tmp/sbomfp/npmws/package-lock.json declares the workspace `blocks/heading` as `@acme/heading` 1.0.0 and the alias `node_modules/@acme/heading` with `"link": true`. Output lists `@acme/heading 1.0.0` under IDENTIFIED and a second `@acme/heading (no version found)` under PARTIALLY IDENTIFIED ("a gap in what you can report"). Total reported as 3 components where 2 exist. Any plugin built with @wordpress/scripts plus npm workspaces hits this.

**Fix as proposed.** Skip entries where `$pkg['link']` is truthy, and skip entries whose key does not contain `node_modules/` (workspace source directories are the product, not dependencies). Also skip `"extraneous"` entries.

### 45. The author's own subdirectories are reported as vendored third-party libraries

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:435 (Scanner::library_candidates), :467-507 (identify_vendored_library)`

The candidate test is a LICENSE file or a composer.json plus any PHP, applied to every direct child of the plugin root. Authors routinely put a copy of the GPL in a subdirectory they also publish separately, and monorepo-style plugins carry composer.json in their own sub-packages. Every such directory is reported as a component with the evidence string "vendored...", which asserts it is third-party code copied in, and gets a version inferred from the author's own docblocks.

**Reproduction.** /tmp/sbomfp/owncode is one plugin with two of its own subdirectories. blocks/ holds a copy of the plugin's GPL LICENSE and render.php with `@version 0.9.0-beta` on a render callback; pro-modules/ holds a composer.json naming the author's own sub-package. Output: `blocks  0.9.0-beta  GPL-2.0  vendored, version read from blocks/render.php` and `bodholdt/owncode-pro-modules  vendored, identified from its own composer.json`. Both are the product itself, counted twice and mislabelled as vendored.

**Fix as proposed.** Require a positive third-party signal before calling a directory vendored: a composer.json whose vendor prefix differs from the root composer.json's, or a LICENSE whose text differs from the root LICENSE, or a name that resolves on Packagist-style `<vendor>/<package>` layout. When only the weak signal is present, emit a note ("blocks/ carries its own LICENSE; if this is your own code it is not a separate component") rather than a component, and never use the word "vendored" in the evidence for a pass-A candidate at the plugin root.

### 46. PHP diagnostics go to STDOUT, so a redirected CycloneDX document is silently invalid JSON

**FIXED** · **Lens:** robustness · **Location at time of review:** `bodholdt-sbom.php:641 (detect_bundled_assets file read); global — the tool never sets display_errors and never suppresses or checks I/O errors`

PHP CLI's default is display_errors=STDOUT (confirmed: 'display_errors => STDOUT => STDOUT' in php:7.4-cli with no php.ini loaded), and the tool emits its document on stdout, so any warning raised during a scan is interleaved into the JSON.

**Reproduction.** Create a plugin tree with assets/locked.js and chmod 000 it, then: php bodholdt-sbom.php /tmp/sbomadv/t7-unreadfile --format=cyclonedx 2>/dev/null > t7.json; exit 0, and t7.json begins 'Warning: file_get_contents(...): Failed to open stream: Permission denied in ... on line 641' followed by the JSON — json_decode() on the result returns null. The same channel carries the array-to-string warnings from a malformed lockfile (lines 308 and 354, demonstrated with a composer.lock whose version field is an array) and the whole stack trace from finding 1. Since the CLI writes both a stderr log line and a stdout display line, '2>/dev/null' does not clean it up.

**Fix as proposed.** Call ini_set('display_errors','stderr') (and set a sane error_reporting) at the top of the script, and guard the file reads — check is_readable()/use @ and fall back to an empty string plus a recorded note — so an unreadable file becomes a reported gap instead of stdout noise.

### 47. A glob metacharacter anywhere in the target path silently disables every glob-based detector

**FIXED** · **Lens:** robustness · **Location at time of review:** `bodholdt-sbom.php:219 (read_plugin_header), 427 (library_candidates), 722 (composer_style_vendor_dirs), 762 (find_files), 565/568 (version_search_order)`

Every directory listing is done with glob() on an unescaped concatenation of the user-supplied root, so characters such as [ ] * ? in the path are interpreted as pattern syntax and the listing silently returns the wrong set (usually nothing), while the SPL-based walk() still sees the real files — producing a confident, gap-free report that omits real components.

**Reproduction.** Same tree copied to two paths. Control: php bodholdt-sbom.php /tmp/sbomadv/t6-control -> '2 shipped components. 2 fully identified, 0 with gaps.' listing acme/widget 4.5.6 (from vendor/acme/widget/composer.json) and superlib 9.9.9. With brackets: php bodholdt-sbom.php '/tmp/sbomadv/t6-meta/plugin [beta]' -> '1 shipped components. 1 fully identified, 0 with gaps.' — acme/widget has vanished entirely, and the plugin header is missed too ('No plugin header, theme header or composer.json found at the top level. Is this the right directory?') even though main.php is right there. Reproduced on macOS/PHP 8.5 and Linux/PHP 7.4.33. Files-scanned count is unaffected, so nothing hints that detection was disabled.

**Fix as proposed.** Escape the fixed directory portion before every glob() call — e.g. a helper that applies addcslashes($dir, '*?[]\\') to the prefix and leaves only the intended pattern unescaped — or replace glob() with scandir()/FilesystemIterator plus an explicit suffix test, which has no pattern semantics at all.

### 48. --diff accepts any JSON object as a CycloneDX document, reporting every component as ADDED

**FIXED** · **Lens:** robustness · **Location at time of review:** `bodholdt-sbom.php:1047-1060 (Diff::load)`

load() only rejects input that is not an array, then reads $data['components'] ?? array(); a valid JSON file that is not a CycloneDX document therefore parses as an SBOM with zero components instead of being rejected.

**Reproduction.** echo '{"hello":"world"}' > notabom.json; php bodholdt-sbom.php --diff notabom.json good.json  ->  'ADDED acme/widget 4.5.6 / ADDED superlib 9.9.9 / 0 changed, 2 added, 0 removed.', exit 0, no warning. Same for '[1,2,3]'. In practice this means pointing --diff at a package.json, a composer.json, or an SPDX document produces a plausible-looking release-over-release change report in which every component in your product is claimed to be new. A file with a nested name/version ({"components":[{"name":["a","b"],"version":{"x":1}}]}) additionally prints 'Array to string conversion' warnings to stdout and reports a component literally called 'Array'. Reproduced on macOS/PHP 8.5 and Linux/PHP 7.4.33.

**Fix as proposed.** Require positive identification before diffing: reject unless $data['bomFormat'] === 'CycloneDX' (or at minimum unless a 'components' key exists), and reuse the existing 'Could not read {$path} as a CycloneDX document.' / exit 2 path. Also skip non-scalar name/version entries instead of casting them.


## Low. Resolved by the high and medium rounds.

### 49. 'Scanned: N files' counts walk iterations, not files, and can be double the true number

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:787 (++$this->files_seen inside Scanner::walk) reported at line 915`

walk() increments files_seen on every yield, and it is called once per contains_php() probe, once per find_version_constant() fallback, and once for detect_bundled_assets(). Files reached by more than one caller are counted more than once, so the header line — the one number a reader uses to sanity-check coverage against their zip — is inflated.

**Reproduction.** Tree with three vendored directories each holding a LICENSE and 120 PHP files with no version constant anywhere (forcing both the contains_php and find_version_constant walks). `find <dir> -type f | wc -l` → 364. Tool prints `Scanned: 733 files`.

**Fix as proposed.** Track distinct paths (a set, or increment only in the single detect_bundled_assets pass), or relabel the line so it does not read as a file count.

### 50. --diff never reports the product's own version change, so a release-to-release comparison can report no changes

**FIXED** · **Lens:** claims · **Location at time of review:** `bodholdt-sbom.php:1047-1054 (Diff::load reads only $data['components'])`

The product itself is written to `metadata.component`, not to `components[]`. Diff::load ignores metadata entirely, so the headline use case in the README ('See what changed between two releases', `--diff sbom-1.4.0.json sbom-1.5.0.json`) reports nothing when the product version is what moved.

**Reproduction.** Two identical plugins differing only in header `Version: 1.4.0` vs `Version: 1.5.0`; produce both CycloneDX docs, then `php bodholdt-sbom.php --diff v1.json v2.json` → `No component changes.` / `0 changed, 0 added, 0 removed.`

**Fix as proposed.** Fold `metadata.component` into the loaded map (labelled as the subject) so a product version bump appears as CHANGED.

### 51. Every licence is emitted as `license.name`, including valid SPDX identifiers and SPDX expressions

**FIXED** · **Lens:** cyclonedx · **Location at time of review:** `bodholdt-sbom.php:864 (CycloneDX::component) — `return array( 'license' => array( 'name' => $l ) );``

CycloneDX 1.6 distinguishes three forms: `license.id` for a valid SPDX identifier, `license.name` for "a commercial or proprietary license or an open source license that may not be defined by SPDX", and a one-element `[{ "expression": ... }]` tuple for an SPDX expression. The tool uses `name` unconditionally, so identifiers it already has verbatim are downgraded to unrecognised custom names, and expressions are stored in a field that cannot express them.

**Reproduction.** Across the eight testbed documents the distinct emitted licence names are 0BSD, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC-BY-4.0, GPL-2.0-or-later, ISC, MIT, MIT-0, MPL-2.0 and `(MIT OR Apache-2.0)`. Checked against CycloneDX's own spdx.schema.json enum, all ten singletons are valid SPDX ids that belong in `id`; `(MIT OR Apache-2.0)` (real, from `@maplibre/mlt@1.1.11` in testbed-plugin-11) is an SPDX expression that belongs in `expression`. Separately, Scanner::sniff_license_file (:603) can emit the bare string `GPL` when the licence text names no version — `GPL` is not an SPDX identifier and is ambiguous between GPL-2.0-only, GPL-2.0-or-later and GPL-3.0.

**Fix as proposed.** Ship the SPDX id list (or a small allow-list of the ids the sniffer can produce) and emit `array( 'license' => array( 'id' => $l ) )` when `$l` is an exact SPDX identifier, `array( 'expression' => $l )` as a single-element array when it contains ` OR `/` AND `/` WITH ` or outer parentheses, and `array( 'license' => array( 'name' => $l ) )` otherwise. Stop emitting bare `GPL`: leave the licence unset and let it appear as a gap, which is what the tool's own design principle calls for.

### 52. The minified-asset sibling check looks only in the same directory, so the author's own build output is asserted to be third-party code

**FIXED** · **Lens:** false-positives · **Location at time of review:** `bodholdt-sbom.php:683-692 (Scanner::identify_asset)`

The "is this the author's own build output" test is `is_file($m[1].'.'.$m[2])`, i.e. foo.js next to foo.min.js in the same directory. The standard src/ to dist/ layout, and any hand-written or Sass-compressed .min.css, defeat it. The resulting entry lands under a heading that states "Third party code is present here".

**Reproduction.** /tmp/sbomfp/minified holds assets/js/src/admin.js and its build output assets/js/dist/admin.min.js, plus a hand-written assets/css/admin.min.css. Both are reported under NOT IDENTIFIED with evidence "minified asset with no banner and no local source, origin unknown". The README describes this check as looking for a local source, which implies more than a same-directory sibling.

**Fix as proposed.** Search the whole tree for a basename match (`admin.js` anywhere under the root) before flagging, and additionally suppress when a sourceMappingURL comment resolves to a file inside the tree or when a package.json build script names the output path. Failing that, reword the section so an unattributed minified file is described as "origin not established" rather than asserted to be third-party.

### 53. --output= with an empty value is an uncaught ValueError fatal on PHP 8, but a clean error on 7.4

**FIXED** · **Lens:** robustness · **Location at time of review:** `bodholdt-sbom.php:1175 (emit)`

emit() only checks for null before calling file_put_contents(), so an empty --output value reaches the function; PHP 8.0+ throws ValueError('Path must not be empty') which nothing catches, while PHP 7.4 returns false and the existing error path handles it — the tool's behaviour on bad input differs across the versions it claims to support.

**Reproduction.** php bodholdt-sbom.php ./t6-control --output=   ->  PHP 8.5: 'PHP Fatal error: Uncaught ValueError: Path must not be empty in ...:1175', full stack trace on stdout, exit 255. PHP 7.4.33: 'Warning: file_put_contents(): Filename cannot be empty', then 'Could not write to ', exit 1.

**Fix as proposed.** Treat an empty --output value as a usage error in main() ('--output needs a filename', return 2) rather than letting it reach file_put_contents().
