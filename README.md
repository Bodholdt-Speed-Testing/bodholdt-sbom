# Bodholdt SBOM

> **All 22 high severity findings from the pre-publication review are fixed in 1.1.0.**
> 26 medium and 5 low remain open, listed in [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

A software bill of materials for a WordPress plugin or theme.

One PHP file. No dependencies. Nothing leaves your machine.

```
php bodholdt-sbom.php ./my-plugin
```

## What it is for

From 11 September 2026, manufacturers of products with digital elements sold into the EU have to
report actively exploited vulnerabilities in their products, with an early warning inside 24 hours
and a full notification inside 72. You cannot do that for a component you cannot name.

If you sell a WordPress plugin or theme, the first practical question is simply: what is actually
inside the thing you ship?

Most tools answer that by reading a lockfile. In WordPress that answer is usually incomplete, because
a great deal of third party code arrives in a plugin by being copied in, with no manifest, no version
file, and nothing for a lockfile-based tool to read.

**So the useful output of this tool is not the list of things it recognised. It is the list of things
it found and could not identify.**

## What it does

It looks at a directory and sorts what it finds into four groups.

**Identified.** Name and version both known. These are the ones you can answer questions about.

**Partially identified.** Found and named, but the version or the licence is missing. Each one is a
gap in what you could report.

**Not identified.** Third party code is present and could not be attributed. This is the list that
matters.

**Present but probably should not ship.** Test and build tooling sitting in shipped scope. Finding
your test framework inside your product is worth knowing before somebody else finds it.

It looks for components in the places they actually turn up:

- The plugin or theme header, for the product itself
- `composer.lock` and `vendor/composer/installed.json`
- `package-lock.json`, with build time dependencies separated from shipped ones
- Libraries copied in wholesale, identified from their own manifest, then from a version constant in
  their source, then from their licence file
- Bundled JavaScript and CSS, from CDN rewrite comments and preserved banners
- Minified assets with no banner and no local source, which are flagged rather than guessed at

## Usage

```
bodholdt-sbom.php <directory> [options]
bodholdt-sbom.php --diff <old.json> <new.json>

  --format=text|cyclonedx   Output format. Default: text.
  --output=<file>           Write to a file instead of standard output.
  --diff <old> <new>        Compare two CycloneDX documents.
  --help
```

Examples:

```bash
# Read the report
php bodholdt-sbom.php ./my-plugin

# Produce a CycloneDX 1.6 document
php bodholdt-sbom.php ./my-plugin --format=cyclonedx --output=sbom.json

# See what changed between two releases
php bodholdt-sbom.php --diff sbom-1.4.0.json sbom-1.5.0.json
```

### Point it at what you ship

Not at your working tree. Your working tree contains your build tooling, and your build tooling is
not part of your product. If it sees a `.git` directory or a `node_modules` directory it will say so.

The most useful place to run it is in your build, on the staged output, just before you make the zip.

## What the output looks like

```
NOT IDENTIFIED (1)
  Third party code is present here and this tool could not attribute
  it. This is the list that matters. You cannot report a vulnerability
  in a component you cannot name.

  stripe-php                         19.0.0
                                     MIT
                                     stripe-php
                                     vendored, version read from stripe-php/lib/Stripe.php
```

That library has no `composer.json`, is not in any lockfile, and its version exists only as a
constant in one file inside it. A tool that reads manifests reports nothing at all here.

## The CycloneDX output

Standard CycloneDX 1.6 JSON, so it feeds the usual tooling. Every component also carries four extra
properties, because a bill of materials that hides its own uncertainty is worse than one that admits
it:

```json
"properties": [
  { "name": "bodholdt:confidence", "value": "partial" },
  { "name": "bodholdt:scope",      "value": "shipped" },
  { "name": "bodholdt:path",       "value": "stripe-php" },
  { "name": "bodholdt:evidence",   "value": "vendored, version read from stripe-php/lib/Stripe.php" }
]
```

If you pass this document to somebody else, they can see how each line was arrived at.

## What it does not do

It does not check for vulnerabilities. It tells you what you have, which is the step before that.

It does not detect code that has been copied in file by file and mixed into your own source. Nothing
can, reliably. If you have done that, you already know, and it belongs on your list by hand.

It does not know whether any legal obligation applies to you. It reports what it can see in a
directory. **It is not legal advice.**

## Requirements

PHP 7.4 or later. That is the whole list.

## Licence

GPL-2.0-or-later. Same as WordPress.

## Who made this

[Bodholdt Labs](https://bodholdtlabs.com). We build and sell WordPress plugins, so we had to answer
this question about our own products first. This is the tool we wrote to do it, and it is free
because the answer is more useful when everybody has it.
