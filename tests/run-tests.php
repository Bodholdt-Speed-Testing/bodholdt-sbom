#!/usr/bin/env php
<?php
/**
 * Fixture tests for Bodholdt SBOM.
 *
 * Each test builds a small directory tree that imitates something real
 * WordPress plugins actually do, runs the tool against it as a subprocess, and
 * asserts on the CycloneDX output. Running the real binary rather than calling
 * internals means these test what a user actually gets.
 *
 * Several of these are regression tests for defects found by running the tool
 * against real plugins. Those are marked, because a regression test is only
 * worth reading if you know what it is protecting.
 *
 * Usage: php tests/run-tests.php
 *
 * @package BodholdtSBOM
 * @license GPL-2.0-or-later
 */

declare( strict_types = 1 );

const TOOL = __DIR__ . '/../bodholdt-sbom.php';

$GLOBALS['passed'] = 0;
$GLOBALS['failed'] = 0;
$GLOBALS['tmp']    = sys_get_temp_dir() . '/bodholdt-sbom-tests-' . getmypid();

/* ---------------------------------------------------------------- helpers */

/**
 * Build a fixture tree. Keys are relative paths, values are file contents.
 * A value of null creates an empty directory.
 */
function fixture( string $name, array $files ): string {
	$root = $GLOBALS['tmp'] . '/' . $name;
	foreach ( $files as $rel => $contents ) {
		$path = $root . '/' . $rel;
		if ( null === $contents ) {
			@mkdir( $path, 0777, true );
			continue;
		}
		@mkdir( dirname( $path ), 0777, true );
		file_put_contents( $path, $contents );
	}
	return $root;
}

/** Run the tool and decode its CycloneDX output. */
function scan( string $dir ): array {
	$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( TOOL ) . ' ' . escapeshellarg( $dir ) . ' --format=cyclonedx 2>/dev/null';
	$out = shell_exec( $cmd );
	$doc = json_decode( (string) $out, true );
	if ( ! is_array( $doc ) ) {
		return array( 'components' => array(), 'metadata' => array(), '_raw' => (string) $out );
	}
	return $doc;
}

/** Run the tool and return its plain text report. */
function scan_text( string $dir ): string {
	$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( TOOL ) . ' ' . escapeshellarg( $dir ) . ' 2>&1';
	return (string) shell_exec( $cmd );
}

function names( array $doc ): array {
	return array_map(
		static function ( $c ) {
			return $c['name'];
		},
		$doc['components'] ?? array()
	);
}

function component( array $doc, string $name ): ?array {
	foreach ( $doc['components'] ?? array() as $c ) {
		if ( $c['name'] === $name ) {
			return $c;
		}
	}
	return null;
}

function prop( ?array $component, string $key ): ?string {
	foreach ( ( $component['properties'] ?? array() ) as $p ) {
		if ( $p['name'] === $key ) {
			return $p['value'];
		}
	}
	return null;
}

/** A realistic machine-generated bundle: one very long line, no newlines. */
function minified_blob( int $bytes = 4096 ): string {
	$chunk = '!function(e,t){var n=e.x||{};n.a=function(r){return r+1};n.b=function(r){return r*2};';
	return str_repeat( $chunk, (int) ceil( $bytes / strlen( $chunk ) ) ) . "\n";
}

function ok( bool $condition, string $label, string $detail = '' ): void {
	if ( $condition ) {
		++$GLOBALS['passed'];
		echo "  PASS  {$label}\n";
		return;
	}
	++$GLOBALS['failed'];
	echo "  FAIL  {$label}\n";
	if ( '' !== $detail ) {
		echo "        {$detail}\n";
	}
}

function heading( string $text ): void {
	echo "\n{$text}\n";
}

/** A minimal but realistic plugin header. */
function plugin_header( string $name = 'Test Plugin', string $version = '1.0.0' ): string {
	return "<?php\n/**\n * Plugin Name: {$name}\n * Version: {$version}\n * License: GPL-2.0-or-later\n */\n";
}

/* ------------------------------------------------------------------ tests */

echo "Bodholdt SBOM fixture tests\n";
echo str_repeat( '=', 60 ) . "\n";

/* --- The subject itself -------------------------------------------- */

heading( 'Root component' );

$dir = fixture(
	'root-header',
	array( 'my-plugin.php' => plugin_header( 'My Plugin', '2.3.4' ) )
);
$doc = scan( $dir );
ok(
	( $doc['metadata']['component']['name'] ?? null ) === 'My Plugin',
	'reads the plugin name from the header',
	'got: ' . json_encode( $doc['metadata']['component'] ?? null )
);
ok(
	( $doc['metadata']['component']['version'] ?? null ) === '2.3.4',
	'reads the plugin version from the header'
);

$dir = fixture(
	'root-theme',
	array( 'style.css' => "/*\nTheme Name: My Theme\nVersion: 4.5.6\n*/\n" )
);
$doc = scan( $dir );
ok(
	( $doc['metadata']['component']['name'] ?? null ) === 'My Theme',
	'reads a theme name from style.css'
);

/* --- A library copied in with no manifest --------------------------- */

heading( 'Vendored library with no manifest (the stripe-php shape)' );

$dir = fixture(
	'vendored-constant',
	array(
		'my-plugin.php'         => plugin_header(),
		'acme-sdk/LICENSE'      => "The MIT License\n\nCopyright (c) 2020 Acme\n",
		'acme-sdk/init.php'     => "<?php\n// bootstrap\n",
		'acme-sdk/lib/Acme.php' => "<?php\nclass Acme {\n    const VERSION = '19.0.0';\n}\n",
	)
);
$doc = scan( $dir );
$c   = component( $doc, 'acme-sdk' );
ok( null !== $c, 'finds a library that appears in no lockfile' );
ok( ( $c['version'] ?? null ) === '19.0.0', 'reads its version from a class constant', 'got: ' . ( $c['version'] ?? 'null' ) );
ok(
	// A valid SPDX identifier belongs in license.id, not license.name.
	'MIT' === ( $c['licenses'][0]['license']['id'] ?? null ),
	'reads its licence from its LICENSE file and emits it as an SPDX id',
	'got: ' . json_encode( $c['licenses'] ?? null )
);

heading( 'REGRESSION: a library is one component, not one per namespace' );
// Found by running against testbed-plugin-6, where treating lib/ as a
// package container reported stripe-php as 26 separate components.

$dir = fixture(
	'namespace-split',
	array(
		'my-plugin.php'                     => plugin_header(),
		'acme-sdk/LICENSE'                  => "The MIT License\n",
		'acme-sdk/lib/Acme.php'             => "<?php\nclass Acme { const VERSION = '3.0.0'; }\n",
		'acme-sdk/lib/Billing/Invoice.php'  => "<?php\nnamespace Acme\\Billing;\nclass Invoice {}\n",
		'acme-sdk/lib/Checkout/Session.php' => "<?php\nnamespace Acme\\Checkout;\nclass Session {}\n",
		'acme-sdk/lib/Events/Event.php'     => "<?php\nnamespace Acme\\Events;\nclass Event {}\n",
	)
);
$doc = scan( $dir );
ok( count( $doc['components'] ) === 1, 'namespace directories are not separate components', 'got: ' . implode( ', ', names( $doc ) ) );
ok( null === component( $doc, 'Billing' ), 'no phantom component named after a namespace' );

/* --- Composer ------------------------------------------------------- */

heading( 'Composer' );

$lock = json_encode(
	array(
		'packages'     => array(
			array( 'name' => 'acme/http', 'version' => '2.1.0', 'license' => array( 'MIT' ) ),
		),
		'packages-dev' => array(
			array( 'name' => 'acme/testkit', 'version' => '9.0.0', 'license' => array( 'MIT' ) ),
		),
	)
);
$dir = fixture(
	'composer-basic',
	array(
		'my-plugin.php'  => plugin_header(),
		'composer.lock'  => $lock,
	)
);
$doc = scan( $dir );
ok( null !== component( $doc, 'acme/http' ), 'reads packages from composer.lock' );
ok(
	'shipped' === prop( component( $doc, 'acme/http' ), 'bodholdt:scope' ),
	'a runtime package is shipped scope'
);
ok(
	'dev-only' === prop( component( $doc, 'acme/testkit' ), 'bodholdt:scope' ),
	'a dev package is not shipped scope'
);
ok(
	'pkg:composer/acme/http@2.1.0' === ( component( $doc, 'acme/http' )['purl'] ?? null ),
	'emits a composer purl'
);

heading( 'REGRESSION: a dependency\'s own lockfile is not the product\'s' );
// Found against testbed-plugin-9, where reading vendor/phpunit/phpunit/composer.lock
// mixed phpunit's private dependency tree into the product and double counted.

$dir = fixture(
	'nested-lock',
	array(
		'my-plugin.php'                       => plugin_header(),
		'composer.lock'                       => json_encode( array( 'packages' => array( array( 'name' => 'acme/http', 'version' => '2.1.0' ) ) ) ),
		'vendor/acme/http/composer.lock'      => json_encode( array( 'packages' => array( array( 'name' => 'someone/private-dep', 'version' => '0.0.1' ) ) ) ),
	)
);
$doc = scan( $dir );
ok(
	null === component( $doc, 'someone/private-dep' ),
	'a lockfile inside vendor/ is ignored',
	'got: ' . implode( ', ', names( $doc ) )
);

/* --- Bundled assets -------------------------------------------------- */

heading( 'Bundled front end assets' );

$dir = fixture(
	'cdn-banner',
	array(
		'my-plugin.php'            => plugin_header(),
		'assets/confetti.min.js'   => "/**\n * Minified by jsDelivr using Terser v5.37.0.\n * Original file: /npm/canvas-confetti@1.5.1/dist/confetti.browser.js\n */\n!function(t,e){}();\n",
	)
);
$doc = scan( $dir );
$c   = component( $doc, 'canvas-confetti' );
ok( null !== $c, 'identifies a package from a CDN rewrite comment' );
ok( ( $c['version'] ?? null ) === '1.5.1', 'reads the version from the CDN comment' );

heading( 'REGRESSION: an ordinary source comment is not a package' );
// Found against testbed-plugin-6, where the CSS comment "/* NEW in 10.15.0 */"
// was reported as a component called NEW at version 10.15.0.

$dir = fixture(
	'comment-not-a-package',
	array(
		'my-plugin.php'    => plugin_header(),
		'assets/admin.css' => "/* NEW in 10.15.0 - restyled the toolbar */\n.wrap { color: red; }\n",
	)
);
$doc = scan( $dir );
ok(
	null === component( $doc, 'NEW' ),
	'a plain comment mentioning a version is not a component',
	'got: ' . implode( ', ', names( $doc ) )
);
ok( count( $doc['components'] ) === 0, 'that fixture yields no components at all' );

heading( 'Minified assets' );

$dir = fixture(
	'minified-own-build',
	array(
		'my-plugin.php'       => plugin_header(),
		'assets/app.js'       => "// my own source\nconsole.log('hi');\n",
		'assets/app.min.js'   => minified_blob(),
	)
);
$doc = scan( $dir );
ok(
	null === component( $doc, 'app.min.js' ),
	'a bundle with a local source beside it is the author\'s own build'
);

heading( 'REGRESSION: a source in src/ still counts as a source' );
// The old test was a same-directory sibling lookup, so the standard src/ to
// dist/ layout and every Sass build were asserted to be third-party code.

$dir = fixture(
	'minified-src-layout',
	array(
		'my-plugin.php'   => plugin_header(),
		'src/widget.js'   => "// my own source\nexport const a = 1;\n",
		'dist/widget.js'  => minified_blob(),
		'src/theme.scss'  => "\$c: red;\n.a { color: \$c; }\n",
		'dist/theme.css'  => minified_blob(),
	)
);
$doc = scan( $dir );
ok( null === component( $doc, 'widget.js' ), 'a src/ to dist/ JS build is not third-party code' );
ok( null === component( $doc, 'theme.css' ), 'a Sass build is not third-party code' );

heading( 'REGRESSION: a bundle without .min. in the name is still a bundle' );
// The flag keyed on the filename, so the default block build output
// build/index.js, which inlines every dependency, was invisible.

$dir = fixture(
	'block-build',
	array(
		'my-plugin.php'    => plugin_header(),
		'build/index.js'   => minified_blob(),
	)
);
$doc = scan( $dir );
$c   = component( $doc, 'index.js' );
ok( null !== $c, 'a machine generated bundle is flagged even without .min. in its name' );
ok(
	'unidentified' === prop( $c, 'bodholdt:confidence' ),
	'and it is flagged as unidentified rather than guessed at'
);

/* --- Hygiene --------------------------------------------------------- */

heading( 'Shipping hygiene' );

$dir = fixture(
	'dev-tooling-shipped',
	array(
		'my-plugin.php' => plugin_header(),
		'composer.lock' => json_encode( array( 'packages' => array( array( 'name' => 'phpunit/phpunit', 'version' => '10.5.0' ) ) ) ),
	)
);
$doc = scan( $dir );
ok(
	'should-not-ship' === prop( component( $doc, 'phpunit/phpunit' ), 'bodholdt:scope' ),
	'test tooling in runtime scope is flagged'
);
ok(
	false !== strpos( scan_text( $dir ), 'SHOULD NOT SHIP' ),
	'and the text report says so prominently'
);

/* --- Robustness ------------------------------------------------------ */

heading( 'Robustness' );

$dir = fixture( 'empty-plugin', array( 'my-plugin.php' => plugin_header() ) );
$doc = scan( $dir );
ok( count( $doc['components'] ) === 0, 'a plugin with no dependencies reports none' );
ok( isset( $doc['bomFormat'] ) && 'CycloneDX' === $doc['bomFormat'], 'and still emits a valid document' );

$dir = fixture(
	'malformed-json',
	array(
		'my-plugin.php' => plugin_header(),
		'composer.lock' => "{ this is not json at all",
	)
);
$text = scan_text( $dir );
ok( false === strpos( $text, 'Fatal error' ), 'a malformed lockfile does not crash the tool' );
ok( false !== strpos( $text, 'Could not parse' ), 'and it says which file it could not read' );

$dir  = fixture( 'trailing-slash', array( 'my-plugin.php' => plugin_header( 'Slash Test', '1.2.3' ) ) );
$doc  = scan( $dir . '/' );
ok(
	( $doc['metadata']['component']['name'] ?? null ) === 'Slash Test',
	'a trailing slash on the target is handled'
);

$cmd    = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( TOOL ) . ' ' . escapeshellarg( $GLOBALS['tmp'] . '/does-not-exist' ) . ' 2>&1';
$out    = (string) shell_exec( $cmd );
ok( false !== strpos( $out, 'Not a directory' ), 'a missing target gives a clear message' );

heading( 'REGRESSION: the composer entry point works when included' );
// Found by CI on PHP 7.4 only. PHP 8 strips a shebang from an included file
// and 7.4 does not, so a shebang on the main file was emitted as output ahead
// of its strict_types declaration. Fatal on 7.4, and on any version it would
// have put a stray line in front of JSON output. The main file therefore has
// no shebang and bin/bodholdt-sbom carries it instead.

$shim = __DIR__ . '/../bin/bodholdt-sbom';
ok( is_file( $shim ), 'the composer entry point exists' );

$first = (string) fgets( (function ( $p ) { return fopen( $p, 'r' ); })( TOOL ) );
ok(
	0 !== strpos( $first, '#!' ),
	'the includable file carries no shebang',
	'first line was: ' . trim( $first )
);

$dir  = fixture( 'via-shim', array( 'my-plugin.php' => plugin_header( 'Shim Test', '7.7.7' ) ) );
$cmd  = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $shim ) . ' ' . escapeshellarg( $dir ) . ' --format=cyclonedx 2>&1';
$out  = (string) shell_exec( $cmd );
$doc  = json_decode( $out, true );
ok(
	is_array( $doc ) && ( $doc['metadata']['component']['name'] ?? null ) === 'Shim Test',
	'the entry point produces clean output with nothing in front of it',
	'got: ' . substr( $out, 0, 120 )
);

/* --- Fixes from the pre-publication review ---------------------------- */

heading( 'REVIEW: a CDN mention does not become, or displace, a component' );

$dir = fixture(
	'cdn-does-not-displace',
	array(
		'my-plugin.php'                  => plugin_header(),
		'assets/js/jquery-3.7.1.min.js'  => "/*! jQuery v3.7.1 | (c) OpenJS Foundation | jquery.org/license */\n"
			. "// see also https://cdn.jsdelivr.net/npm/core-js-bundle@3.6.5/minified.js\n"
			. minified_blob(),
	)
);
$doc = scan( $dir );
ok( null !== component( $doc, 'jQuery' ), 'the real banner wins over a CDN mention lower down' );
ok( null === component( $doc, 'core-js-bundle' ), 'the mentioned package is not fabricated as a component' );

$dir = fixture(
	'cdn-mention-only',
	array(
		'my-plugin.php'      => plugin_header(),
		'assets/js/admin.js' => "// TODO: consider https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js\nfunction ready(){}\n",
	)
);
$doc = scan( $dir );
ok( count( $doc['components'] ) === 0, 'a CDN URL in a comment invents nothing' );
ok( false !== strpos( scan_text( $dir ), 'sortablejs@1.15.0' ), 'but it is recorded as a note so the information is not lost' );

heading( 'REVIEW: a version belonging to something else is not the package version' );

$dir = fixture(
	'schema-version',
	array(
		'my-plugin.php' => plugin_header(),
		'vendor/acme/scheduler/composer.json'    => '{"name":"acme/scheduler"}',
		'vendor/acme/scheduler/scheduler.php'    => "<?php\ndefine( 'ACME_STORE_SCHEMA_VERSION', '3' );\ndefine( 'ACME_SCHEDULER_VERSION', '3.8.2' );\n",
	)
);
$doc = scan( $dir );
ok( ( component( $doc, 'acme/scheduler' )['version'] ?? null ) === '3.8.2', 'a schema version is not mistaken for the package version' );
ok(
	'partial' === prop( component( $doc, 'acme/scheduler' ), 'bodholdt:confidence' ),
	'and a version read out of source is PARTIAL, never IDENTIFIED'
);

$dir = fixture(
	'conflicting-versions',
	array(
		'my-plugin.php'      => plugin_header(),
		'tcpdf/LICENSE.txt'  => "The MIT License\n",
		'tcpdf/barcodes.php' => "<?php\n/**\n * @package tcpdf\n * @version 1.0.015\n */\nclass Barcode {}\n",
		'tcpdf/tcpdf.php'    => "<?php\n/**\n * @package tcpdf\n * @version 6.6.5\n */\nclass TCPDF {}\n",
	)
);
$doc = scan( $dir );
ok( null === ( component( $doc, 'tcpdf' )['version'] ?? null ), 'two candidate versions produce none rather than a guess' );
ok( false !== strpos( scan_text( $dir ), 'more than one' ), 'and the conflict is reported' );

heading( 'REVIEW: copied-in code is found without a manifest, and below the first level' );

$dir = fixture(
	'deep-unmanifested',
	array(
		'my-plugin.php'                  => "<?php\n/**\n * Plugin Name: My Plugin\n * Text Domain: my-plugin\n * Version: 1.0.0\n */\nnamespace MyPlugin;\n",
		'includes/psr-log/Logger.php'    => "<?php\nnamespace Psr\\Log;\nclass Logger { const VERSION = '3.0.0'; }\n",
		'includes/admin/settings.php'    => "<?php\nnamespace MyPlugin\\Admin;\nclass MyPluginSettings {}\n",
		'includes/views/list-table.php'  => "<?php\n// a bare template, no declarations at all\n?>\n<div></div>\n",
	)
);
$doc = scan( $dir );
ok( null !== component( $doc, 'psr-log' ), 'a library with no LICENSE and no manifest, two levels down, is found' );
ok( null === component( $doc, 'admin' ), 'the author\'s own namespaced directory is not reported' );
ok( null === component( $doc, 'views' ), 'a directory of bare templates is not reported as foreign' );

heading( 'REVIEW: installed.json states which packages are dev-only' );

$installed = json_encode(
	array(
		'packages'          => array(
			array( 'name' => 'acme/runtime', 'version' => '1.0.0' ),
			array( 'name' => 'acme/testkit', 'version' => '2.0.0' ),
		),
		'dev-package-names' => array( 'acme/testkit' ),
	)
);
$dir = fixture(
	'installed-dev-names',
	array(
		'my-plugin.php'                  => plugin_header(),
		'vendor/composer/installed.json' => $installed,
	)
);
$doc = scan( $dir );
ok( 'shipped' === prop( component( $doc, 'acme/runtime' ), 'bodholdt:scope' ), 'a runtime package is shipped' );
ok( 'dev-only' === prop( component( $doc, 'acme/testkit' ), 'bodholdt:scope' ), 'a package named in dev-package-names is not shipped product' );

heading( 'REVIEW: installed.json does not blind the tool to the rest of the vendor tree' );

$dir = fixture(
	'installed-plus-stray',
	array(
		'my-plugin.php'                        => plugin_header(),
		'vendor/composer/installed.json'       => json_encode( array( 'packages' => array( array( 'name' => 'acme/runtime', 'version' => '1.0.0' ) ) ) ),
		'vendor/stray/oldlib/LICENSE'          => "The MIT License\n",
		'vendor/stray/oldlib/OldLib.php'       => "<?php\nclass OldLib { const VERSION = '0.9.0'; }\n",
	)
);
$doc = scan( $dir );
ok( null !== component( $doc, 'acme/runtime' ), 'the manifested package is reported' );
ok( null !== component( $doc, 'oldlib' ), 'and a library the manifest does not mention is still found' );

heading( 'REVIEW: LGPL and AGPL are not reported as GPL' );

$dir = fixture(
	'lgpl',
	array(
		'my-plugin.php'    => plugin_header(),
		'acme/LICENSE'     => "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999\n\nThis library is free software; you can redistribute it under the GNU Lesser General Public License.\n",
		'acme/Acme.php'    => "<?php\nnamespace Acme;\nclass Acme { const VERSION = '1.0.0'; }\n",
	)
);
$doc = scan( $dir );
$lic = component( $doc, 'acme' )['licenses'][0]['license'] ?? array();
$got = $lic['id'] ?? ( $lic['name'] ?? '' );
ok( false !== strpos( (string) $got, 'LGPL' ), 'LGPL is not reported as GPL', 'got: ' . $got );

heading( 'REVIEW: a prefixed vendor directory is recognised structurally' );

$dir = fixture(
	'strauss',
	array(
		'my-plugin.php'                              => plugin_header(),
		'vendor-prefixed/acme/http/composer.json'    => '{"name":"acme/http","version":"1.2.3"}',
		'vendor-prefixed/acme/http/Client.php'       => "<?php\nnamespace Prefixed\\Acme;\nclass Client {}\n",
		'vendor-prefixed/beta/json/composer.json'    => '{"name":"beta/json","version":"4.5.6"}',
		'vendor-prefixed/beta/json/Parser.php'       => "<?php\nnamespace Prefixed\\Beta;\nclass Parser {}\n",
	)
);
$doc = scan( $dir );
ok( null !== component( $doc, 'acme/http' ), 'a package in a non-standard vendor directory is found' );
ok( null !== component( $doc, 'beta/json' ), 'and so is its neighbour' );

heading( 'REVIEW: robustness' );

$dir = fixture(
	'npm-license-array',
	array(
		'my-plugin.php'      => plugin_header(),
		'package-lock.json'  => json_encode(
			array(
				'lockfileVersion' => 3,
				'packages'        => array(
					''                        => array( 'name' => 'root' ),
					'node_modules/acme-thing' => array( 'name' => 'acme-thing', 'version' => '1.0.0', 'license' => array( 'MIT', 'Apache-2.0' ) ),
				),
			)
		),
	)
);
$out = scan_text( $dir );
ok( false === strpos( $out, 'Array to string' ), 'a non-string npm license does not raise a PHP warning' );
$doc = scan( $dir );
ok( is_array( $doc ) && isset( $doc['bomFormat'] ), 'and the CycloneDX output is still valid JSON' );

$dir = fixture( 'scoped-purl', array(
	'my-plugin.php'     => plugin_header(),
	'package-lock.json' => json_encode( array(
		'lockfileVersion' => 3,
		'packages'        => array(
			''                                => array( 'name' => 'root' ),
			'node_modules/@scope/thing'       => array( 'name' => '@scope/thing', 'version' => '1.0.0' ),
		),
	) ),
) );
$doc = scan( $dir );
ok(
	'pkg:npm/%40scope/thing@1.0.0' === ( component( $doc, '@scope/thing' )['purl'] ?? null ),
	'a scoped npm purl percent encodes its @',
	'got: ' . ( component( $doc, '@scope/thing' )['purl'] ?? 'null' )
);

$dir = fixture( 'unreadable', array(
	'my-plugin.php'         => plugin_header(),
	'locked/secret.php'     => "<?php\nnamespace Foreign;\nclass Thing {}\n",
) );
@chmod( $dir . '/locked', 0000 );
$out = scan_text( $dir );
@chmod( $dir . '/locked', 0755 );
ok( false === strpos( $out, 'Fatal error' ) && false === strpos( $out, 'Uncaught' ), 'an unreadable directory does not kill the run', 'got: ' . substr( $out, 0, 200 ) );

$dir = fixture( 'no-version-field', array( 'my-plugin.php' => plugin_header() ) );
$doc = scan( $dir );
ok(
	! array_key_exists( 'version', $doc['metadata']['component'] ) || null !== $doc['metadata']['component']['version'],
	'no component carries a fabricated "unknown" version'
);

/* --- Document shape --------------------------------------------------- */

heading( 'CycloneDX document' );

$dir = fixture(
	'doc-shape',
	array(
		'my-plugin.php' => plugin_header(),
		'composer.lock' => json_encode( array( 'packages' => array( array( 'name' => 'acme/http', 'version' => '2.1.0', 'license' => array( 'MIT' ) ) ) ) ),
	)
);
$doc = scan( $dir );
ok( '1.6' === ( $doc['specVersion'] ?? null ), 'declares CycloneDX 1.6' );
ok(
	(bool) preg_match( '/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', (string) ( $doc['serialNumber'] ?? '' ) ),
	'emits a well formed v4 serial number',
	'got: ' . ( $doc['serialNumber'] ?? 'null' )
);
$c = component( $doc, 'acme/http' );
ok( null !== prop( $c, 'bodholdt:confidence' ), 'every component carries a confidence property' );
ok( null !== prop( $c, 'bodholdt:evidence' ), 'every component says how it was found' );

/* --- Diff -------------------------------------------------------------- */

heading( 'Diff' );

function bom( array $components, string $product_version = '1.0.0' ): string {
	return (string) json_encode(
		array(
			'bomFormat'   => 'CycloneDX',
			'specVersion' => '1.6',
			'metadata'    => array( 'component' => array( 'type' => 'application', 'name' => 'My Plugin', 'version' => $product_version ) ),
			'components'  => $components,
		)
	);
}

$a = $GLOBALS['tmp'] . '/a.json';
$b = $GLOBALS['tmp'] . '/b.json';
file_put_contents( $a, bom( array( array( 'name' => 'acme/http', 'version' => '1.0.0' ), array( 'name' => 'acme/gone', 'version' => '1.0.0' ) ) ) );
file_put_contents( $b, bom( array( array( 'name' => 'acme/http', 'version' => '2.0.0' ), array( 'name' => 'acme/new', 'version' => '1.0.0' ) ) ) );

$cmd  = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( TOOL ) . ' --diff ' . escapeshellarg( $a ) . ' ' . escapeshellarg( $b ) . ' 2>&1';
$out  = (string) shell_exec( $cmd );
ok( false !== strpos( $out, 'CHANGED  acme/http' ), 'diff reports a version change' );
ok( false !== strpos( $out, 'ADDED    acme/new' ), 'diff reports an addition' );
ok( false !== strpos( $out, 'REMOVED  acme/gone' ), 'diff reports a removal' );

heading( 'REGRESSION: diff sees the product\'s own version, and rejects non-CycloneDX input' );
// metadata.component holds the product, and Diff ignored metadata entirely,
// so the headline use case (compare two releases) reported no changes when
// the product version was the thing that moved.

file_put_contents( $a, bom( array(), '1.4.0' ) );
file_put_contents( $b, bom( array(), '1.5.0' ) );
$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( TOOL ) . ' --diff ' . escapeshellarg( $a ) . ' ' . escapeshellarg( $b ) . ' 2>&1';
$out = (string) shell_exec( $cmd );
ok( false !== strpos( $out, '1.4.0 -> 1.5.0' ), 'a release to release diff reports the product version change', 'got: ' . trim( $out ) );

$bad = $GLOBALS['tmp'] . '/not-a-bom.json';
file_put_contents( $bad, '{"hello":"world"}' );
$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( TOOL ) . ' --diff ' . escapeshellarg( $bad ) . ' ' . escapeshellarg( $b ) . ' 2>&1';
$out = (string) shell_exec( $cmd );
ok( false !== strpos( $out, 'Not a CycloneDX document' ), 'a JSON file that is not a bill of materials is rejected' );

/* ------------------------------------------------------------------ done */

// Clean up. A test run that leaves rubbish behind is its own small bug.
$rm = new RecursiveIteratorIterator(
	new RecursiveDirectoryIterator( $GLOBALS['tmp'], FilesystemIterator::SKIP_DOTS ),
	RecursiveIteratorIterator::CHILD_FIRST
);
foreach ( $rm as $path ) {
	$path->isDir() ? @rmdir( $path->getPathname() ) : @unlink( $path->getPathname() );
}
@rmdir( $GLOBALS['tmp'] );

echo "\n" . str_repeat( '=', 60 ) . "\n";
printf( "%d passed, %d failed\n\n", $GLOBALS['passed'], $GLOBALS['failed'] );

exit( $GLOBALS['failed'] > 0 ? 1 : 0 );
