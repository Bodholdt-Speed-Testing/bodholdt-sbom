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

function prop( array $component, string $key ): ?string {
	foreach ( $component['properties'] ?? array() as $p ) {
		if ( $p['name'] === $key ) {
			return $p['value'];
		}
	}
	return null;
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
	'MIT' === ( $c['licenses'][0]['license']['name'] ?? null ),
	'reads its licence from its LICENSE file'
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
		'assets/app.min.js'   => "console.log('hi');\n",
	)
);
$doc = scan( $dir );
ok(
	null === component( $doc, 'app.min.js' ),
	'a minified file with a local source beside it is the author\'s own build'
);

$dir = fixture(
	'minified-orphan',
	array(
		'my-plugin.php'          => plugin_header(),
		'assets/mystery.min.js'  => "!function(){var a=1}();\n",
	)
);
$doc = scan( $dir );
$c   = component( $doc, 'mystery.min.js' );
ok( null !== $c, 'a minified file with no source and no banner is flagged' );
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

$a = $GLOBALS['tmp'] . '/a.json';
$b = $GLOBALS['tmp'] . '/b.json';
file_put_contents( $a, json_encode( array( 'components' => array( array( 'name' => 'acme/http', 'version' => '1.0.0' ), array( 'name' => 'acme/gone', 'version' => '1.0.0' ) ) ) ) );
file_put_contents( $b, json_encode( array( 'components' => array( array( 'name' => 'acme/http', 'version' => '2.0.0' ), array( 'name' => 'acme/new', 'version' => '1.0.0' ) ) ) ) );

$cmd  = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( TOOL ) . ' --diff ' . escapeshellarg( $a ) . ' ' . escapeshellarg( $b ) . ' 2>&1';
$out  = (string) shell_exec( $cmd );
ok( false !== strpos( $out, 'CHANGED  acme/http' ), 'diff reports a version change' );
ok( false !== strpos( $out, 'ADDED    acme/new' ), 'diff reports an addition' );
ok( false !== strpos( $out, 'REMOVED  acme/gone' ), 'diff reports a removal' );

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
