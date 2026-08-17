<?php
/**
 * Bodholdt SBOM
 *
 * Run it as `php bodholdt-sbom.php <directory>`.
 *
 * There is deliberately no shebang on this file. PHP 7.4 does not strip a
 * shebang when a file is included, so it would be emitted as output ahead of
 * the strict_types declaration below, which is both a fatal error on 7.4 and a
 * way to corrupt JSON output with a stray line. The executable entry point with
 * the shebang lives in bin/bodholdt-sbom.
 *
 * Produces a software bill of materials for a WordPress plugin or theme.
 *
 * The point of this tool is not the list of components it recognises. Plenty of
 * tools read a lockfile. The point is the code it finds and CANNOT identify,
 * because in a WordPress plugin most third party code arrives by being copied
 * in, with no manifest, and that is precisely the code nobody can account for.
 *
 * This tool reports what it identified, what it identified only partially, what
 * it could not identify at all, and what looks like it should not be shipping.
 * The last three categories are the ones worth your attention.
 *
 * Requires PHP 7.4 or later. No dependencies.
 *
 * @package BodholdtSBOM
 * @license GPL-2.0-or-later
 */

declare( strict_types = 1 );

namespace Bodholdt\SBOM;

const VERSION = '1.0.0';

/* -------------------------------------------------------------------------
 * Component model
 * ---------------------------------------------------------------------- */

/**
 * How sure we are about a component.
 *
 * IDENTIFIED   name and version both known
 * PARTIAL      found and named, but the version or licence is missing
 * UNIDENTIFIED third party code detected, not attributable to a known package
 */
const IDENTIFIED   = 'identified';
const PARTIAL      = 'partial';
const UNIDENTIFIED = 'unidentified';

/** Scope: does this code actually ship inside the product? */
const SHIPPED   = 'shipped';
const DEV_ONLY  = 'dev-only';
const SUSPICION = 'should-not-ship';

final class Component {
	public string $name;
	public ?string $version   = null;
	public array $licenses    = array();
	public ?string $purl      = null;
	public string $confidence = UNIDENTIFIED;
	public string $scope      = SHIPPED;
	public string $path       = '';
	public string $evidence   = '';
	public string $type       = 'library';

	public function __construct( string $name ) {
		$this->name = $name;
	}

	public function key(): string {
		return strtolower( $this->name ) . '@' . ( $this->version ?? '?' );
	}
}

/* -------------------------------------------------------------------------
 * Scanner
 * ---------------------------------------------------------------------- */

final class Scanner {

	/** Directories never worth walking into for component detection. */
	private const SKIP_DIRS = array( '.git', '.svn', '.hg', '.idea', '.vscode', '__MACOSX' );

	/**
	 * Directory names that hold SEVERAL third party packages side by side.
	 *
	 * Deliberately excludes lib, libs and library. Those are nearly always one
	 * library's own internal structure, and treating their children as packages
	 * turns a single dependency into one phantom component per namespace.
	 */
	private const VENDOR_DIRS = array( 'vendor', 'vendors', 'third-party', 'thirdparty', '3rdparty', 'external' );

	/**
	 * Packages that are build or test tooling. Finding these inside a tree that
	 * is meant to ship is a finding in its own right, not a component.
	 */
	private const DEV_TOOLING = array(
		'phpunit/phpunit', 'squizlabs/php_codesniffer', 'wp-coding-standards/wpcs',
		'phpstan/phpstan', 'vimeo/psalm', 'mockery/mockery', 'friendsofphp/php-cs-fixer',
		'phpcsstandards/phpcsutils', 'phpcsstandards/phpcsextra', 'sebastian/diff',
		'phpspec/prophecy', 'yoast/phpunit-polyfills', 'dealerdirect/phpcodesniffer-composer-installer',
	);

	/** Words that appear in ordinary source comments and are not package names. */
	private const BANNER_STOPWORDS = array(
		'new', 'version', 'updated', 'added', 'fixed', 'changed', 'since', 'note',
		'todo', 'deprecated', 'see', 'requires', 'style', 'styles', 'theme', 'admin',
	);

	private string $root;
	private array $components = array();
	private array $notes      = array();
	private array $claimed    = array();
	private int $files_seen   = 0;

	public function __construct( string $root ) {
		$this->root = rtrim( $root, '/' );
	}

	public function scan(): array {
		$this->detect_root_component();
		$this->detect_composer();
		$this->detect_npm();
		$this->detect_vendored_php();
		$this->detect_bundled_assets();
		$this->detect_shipping_hygiene();

		return array(
			'components' => array_values( $this->components ),
			'notes'      => $this->notes,
			'files_seen' => $this->files_seen,
		);
	}

	private function add( Component $c ): void {
		// Identity is the package, not where it was spotted. Two detectors
		// finding the same name and version have found one component, and
		// keying on the path as well reports it twice.
		$key = $c->key();

		if ( isset( $this->components[ $key ] ) ) {
			$existing = $this->components[ $key ];
			if ( $this->rank( $c->confidence ) <= $this->rank( $existing->confidence ) ) {
				// Keep the stronger record, but never lose a should-not-ship flag.
				if ( SUSPICION === $c->scope ) {
					$existing->scope = SUSPICION;
				}
				return;
			}
			if ( SUSPICION === $existing->scope ) {
				$c->scope = SUSPICION;
			}
		}
		$this->components[ $key ] = $c;
	}

	private function rank( string $confidence ): int {
		switch ( $confidence ) {
			case IDENTIFIED:
				return 3;
			case PARTIAL:
				return 2;
			default:
				return 1;
		}
	}

	private function note( string $message ): void {
		$this->notes[] = $message;
	}

	private function rel( string $path ): string {
		$rel = substr( $path, strlen( $this->root ) );
		return ltrim( $rel, '/' ) ?: '.';
	}

	/* --------------------------------------------------------------------
	 * 1. The subject itself
	 * ----------------------------------------------------------------- */

	private function detect_root_component(): void {
		$found = $this->read_plugin_header() ?? $this->read_theme_header();

		if ( null === $found ) {
			$composer = $this->read_json( $this->root . '/composer.json' );
			if ( is_array( $composer ) && isset( $composer['name'] ) ) {
				$found = array(
					'name'     => (string) $composer['name'],
					'version'  => isset( $composer['version'] ) ? (string) $composer['version'] : null,
					'license'  => isset( $composer['license'] ) ? (string) ( is_array( $composer['license'] ) ? reset( $composer['license'] ) : $composer['license'] ) : null,
					'evidence' => 'composer.json',
				);
			}
		}

		if ( null === $found ) {
			$this->note( 'No plugin header, theme header or composer.json found at the top level. Is this the right directory?' );
			$found = array(
				'name'     => basename( $this->root ),
				'version'  => null,
				'license'  => null,
				'evidence' => 'directory name, as a last resort',
			);
		}

		$c             = new Component( $found['name'] );
		$c->type       = 'application';
		$c->version    = $found['version'];
		$c->licenses   = $found['license'] ? array( $found['license'] ) : array();
		$c->confidence = $found['version'] ? IDENTIFIED : PARTIAL;
		$c->path       = '.';
		$c->evidence   = $found['evidence'];
		$this->add( $c );
	}

	/** Parse a WordPress plugin header from any top level PHP file. */
	private function read_plugin_header(): ?array {
		foreach ( glob( $this->root . '/*.php' ) ?: array() as $file ) {
			$head = (string) file_get_contents( $file, false, null, 0, 8192 );
			if ( ! preg_match( '/^[\s\*\/#@]*Plugin Name\s*:\s*(.+)$/mi', $head, $m ) ) {
				continue;
			}
			$name    = trim( $m[1] );
			$version = preg_match( '/^[\s\*\/#@]*Version\s*:\s*(.+)$/mi', $head, $v ) ? trim( $v[1] ) : null;
			$license = preg_match( '/^[\s\*\/#@]*License\s*:\s*(.+)$/mi', $head, $l ) ? trim( $l[1] ) : null;

			return array(
				'name'     => $name,
				'version'  => $version,
				'license'  => $license,
				'evidence' => 'plugin header in ' . basename( $file ),
			);
		}
		return null;
	}

	/** Parse a WordPress theme header from style.css. */
	private function read_theme_header(): ?array {
		$style = $this->root . '/style.css';
		if ( ! is_file( $style ) ) {
			return null;
		}
		$head = (string) file_get_contents( $style, false, null, 0, 8192 );
		if ( ! preg_match( '/^[\s\*\/#@]*Theme Name\s*:\s*(.+)$/mi', $head, $m ) ) {
			return null;
		}
		return array(
			'name'     => trim( $m[1] ),
			'version'  => preg_match( '/^[\s\*\/#@]*Version\s*:\s*(.+)$/mi', $head, $v ) ? trim( $v[1] ) : null,
			'license'  => preg_match( '/^[\s\*\/#@]*License\s*:\s*(.+)$/mi', $head, $l ) ? trim( $l[1] ) : null,
			'evidence' => 'theme header in style.css',
		);
	}

	/* --------------------------------------------------------------------
	 * 2. Composer
	 * ----------------------------------------------------------------- */

	private function detect_composer(): void {
		// vendor/composer/installed.json records what is actually on disk, which
		// is a better answer than the lockfile when only the vendor dir shipped.
		foreach ( $this->composer_style_vendor_dirs() as $vendor_dir ) {
			$installed = $this->read_json( $vendor_dir . '/composer/installed.json' );
			if ( ! is_array( $installed ) ) {
				continue;
			}
			// Composer 2 nests under "packages"; composer 1 was a bare list.
			$packages = isset( $installed['packages'] ) ? (array) $installed['packages'] : $installed;

			foreach ( $packages as $pkg ) {
				if ( ! is_array( $pkg ) || ! isset( $pkg['name'] ) ) {
					continue;
				}
				$name          = (string) $pkg['name'];
				$c             = new Component( $name );
				$c->version    = isset( $pkg['version'] ) ? (string) $pkg['version'] : null;
				$c->licenses   = array_map( 'strval', (array) ( $pkg['license'] ?? array() ) );
				$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
				$c->path       = $this->rel( $vendor_dir );
				$c->purl       = $c->version ? 'pkg:composer/' . $name . '@' . $c->version : null;
				$c->evidence   = 'vendor/composer/installed.json';
				$c->scope      = in_array( strtolower( $name ), self::DEV_TOOLING, true ) ? SUSPICION : SHIPPED;
				$this->add( $c );
				$this->claimed[] = $vendor_dir;
			}
		}

		foreach ( $this->find_files( 'composer.lock', 4 ) as $lock_path ) {
			// A lockfile inside a vendor directory belongs to a dependency and
			// describes ITS dependencies, not this product's. Reading it mixes a
			// package's private tree into the product's bill of materials.
			if ( preg_match( '#/(vendor|node_modules)/#', $lock_path ) ) {
				continue;
			}
			$lock = $this->read_json( $lock_path );
			if ( ! is_array( $lock ) ) {
				continue;
			}
			$dir = $this->rel( dirname( $lock_path ) );

			foreach ( array( 'packages' => SHIPPED, 'packages-dev' => DEV_ONLY ) as $section => $scope ) {
				foreach ( (array) ( $lock[ $section ] ?? array() ) as $pkg ) {
					if ( ! isset( $pkg['name'] ) ) {
						continue;
					}
					$c             = new Component( (string) $pkg['name'] );
					$c->version    = isset( $pkg['version'] ) ? (string) $pkg['version'] : null;
					$c->licenses   = array_map( 'strval', (array) ( $pkg['license'] ?? array() ) );
					$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
					$c->scope      = $scope;
					$c->path       = $dir;
					$c->purl       = $c->version ? 'pkg:composer/' . $pkg['name'] . '@' . $c->version : null;
					$c->evidence   = 'composer.lock (' . $section . ')';

					if ( SHIPPED === $scope && in_array( strtolower( (string) $pkg['name'] ), self::DEV_TOOLING, true ) ) {
						$c->scope = SUSPICION;
					}
					$this->add( $c );
				}
			}
		}
	}

	/* --------------------------------------------------------------------
	 * 3. npm
	 * ----------------------------------------------------------------- */

	private function detect_npm(): void {
		foreach ( $this->find_files( 'package-lock.json', 4 ) as $lock_path ) {
			$lock = $this->read_json( $lock_path );
			if ( ! is_array( $lock ) ) {
				continue;
			}
			$dir = $this->rel( dirname( $lock_path ) );

			// A node_modules directory that is absent means these are build time only.
			$ships = is_dir( dirname( $lock_path ) . '/node_modules' );
			if ( ! $ships ) {
				$this->note( sprintf(
					'%s: node dependencies recorded but node_modules is not present, so they are treated as build time only. If your build inlines them into a shipped bundle, they are part of your product and this tool cannot see that.',
					$dir
				) );
			}

			// lockfileVersion 2 and 3 use "packages"; version 1 uses "dependencies".
			$packages = (array) ( $lock['packages'] ?? array() );
			if ( $packages ) {
				foreach ( $packages as $rel_path => $pkg ) {
					if ( '' === $rel_path || ! is_array( $pkg ) ) {
						continue; // The empty key is the project itself.
					}
					$name          = $pkg['name'] ?? preg_replace( '#^.*node_modules/#', '', (string) $rel_path );
					$c             = new Component( (string) $name );
					$c->version    = isset( $pkg['version'] ) ? (string) $pkg['version'] : null;
					$c->licenses   = isset( $pkg['license'] ) ? array( (string) $pkg['license'] ) : array();
					$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
					$c->scope      = ( $ships && empty( $pkg['dev'] ) ) ? SHIPPED : DEV_ONLY;
					$c->path       = $dir;
					$c->purl       = $c->version ? 'pkg:npm/' . $name . '@' . $c->version : null;
					$c->evidence   = 'package-lock.json';
					$this->add( $c );
				}
			} else {
				foreach ( (array) ( $lock['dependencies'] ?? array() ) as $name => $pkg ) {
					$c             = new Component( (string) $name );
					$c->version    = isset( $pkg['version'] ) ? (string) $pkg['version'] : null;
					$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
					$c->scope      = ( $ships && empty( $pkg['dev'] ) ) ? SHIPPED : DEV_ONLY;
					$c->path       = $dir;
					$c->purl       = $c->version ? 'pkg:npm/' . $name . '@' . $c->version : null;
					$c->evidence   = 'package-lock.json (v1)';
					$this->add( $c );
				}
			}
		}
	}

	/* --------------------------------------------------------------------
	 * 4. Vendored PHP, the part that matters
	 * ----------------------------------------------------------------- */

	private function detect_vendored_php(): void {
		// Pass A: a whole library copied in, recognised by carrying its own
		// licence or manifest. The library is ONE component. The directories
		// inside it are its namespaces, not separate packages, so its whole
		// subtree is claimed and nothing below it is reported again.
		foreach ( $this->library_candidates() as $dir ) {
			if ( $this->is_claimed( $dir ) ) {
				continue;
			}
			$this->add( $this->identify_vendored_library( $dir ) );
			$this->claimed[] = $dir;
		}

		// Pass B: composer-shaped vendor directories, where the children really
		// are separate packages, laid out as vendor/<publisher>/<package>.
		foreach ( $this->composer_style_vendor_dirs() as $dir ) {
			if ( is_file( $dir . '/composer/installed.json' ) ) {
				continue; // Authoritative manifest, handled by the composer pass.
			}
			foreach ( glob( $dir . '/*', GLOB_ONLYDIR ) ?: array() as $publisher ) {
				$packages = glob( $publisher . '/*', GLOB_ONLYDIR ) ?: array();
				foreach ( $packages ?: array( $publisher ) as $pkg_dir ) {
					if ( $this->is_claimed( $pkg_dir ) || ! $this->contains_php( $pkg_dir ) ) {
						continue;
					}
					$this->add( $this->identify_vendored_library( $pkg_dir ) );
					$this->claimed[] = $pkg_dir;
				}
			}
		}
	}

	/**
	 * Directories that look like a third party library dropped in wholesale.
	 *
	 * The test is deliberately conservative: it must contain PHP and carry
	 * either its own licence file or its own manifest. Guessing more loosely
	 * turns every subdirectory of a large library into a phantom component.
	 */
	private function library_candidates(): array {
		$found = array();
		$roots = array_merge( array( $this->root ), $this->composer_style_vendor_dirs() );

		foreach ( $roots as $base ) {
			foreach ( glob( $base . '/*', GLOB_ONLYDIR ) ?: array() as $dir ) {
				$name = strtolower( basename( $dir ) );
				if ( in_array( $name, self::SKIP_DIRS, true ) || 'node_modules' === $name ) {
					continue;
				}
				if ( $base === $this->root && in_array( $name, self::VENDOR_DIRS, true ) ) {
					continue; // Containers are handled by pass B.
				}
				if ( ( $this->has_license_file( $dir ) || is_file( $dir . '/composer.json' ) ) && $this->contains_php( $dir ) ) {
					$found[] = $dir;
				}
			}
		}
		return array_unique( $found );
	}

	private function has_license_file( string $dir ): bool {
		foreach ( array( 'LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING', 'LICENCE' ) as $name ) {
			if ( is_file( $dir . '/' . $name ) ) {
				return true;
			}
		}
		return false;
	}

	private function is_claimed( string $path ): bool {
		foreach ( $this->claimed as $claimed ) {
			if ( 0 === strpos( $path, $claimed . '/' ) || $path === $claimed ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Work out what a copied-in library is, from whatever evidence exists.
	 *
	 * In order of reliability: its own composer.json, a version constant in its
	 * source, a version in a docblock, then nothing at all.
	 */
	private function identify_vendored_library( string $dir ): Component {
		$name = basename( $dir );
		$c    = new Component( $name );
		$c->path  = $this->rel( $dir );
		$c->scope = SHIPPED;

		$composer = $this->read_json( $dir . '/composer.json' );
		if ( is_array( $composer ) && isset( $composer['name'] ) ) {
			$c->name       = (string) $composer['name'];
			$c->version    = isset( $composer['version'] ) ? (string) $composer['version'] : null;
			$c->licenses   = array_map( 'strval', (array) ( $composer['license'] ?? array() ) );
			$c->evidence   = 'vendored, identified from its own composer.json';
			$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
		}

		if ( null === $c->version ) {
			$found = $this->find_version_constant( $dir );
			if ( null !== $found ) {
				$c->version    = $found['version'];
				$c->evidence   = 'vendored, version read from ' . $found['file'];
				$c->confidence = PARTIAL; // Named by directory, version by inference.
				if ( is_array( $composer ) && isset( $composer['name'] ) ) {
					$c->confidence = IDENTIFIED;
				}
			}
		}

		if ( ! $c->licenses ) {
			$license = $this->sniff_license_file( $dir );
			if ( null !== $license ) {
				$c->licenses = array( $license );
			}
		}

		if ( '' === $c->evidence ) {
			$c->evidence   = 'vendored directory containing PHP, not attributable to a known package';
			$c->confidence = UNIDENTIFIED;
		}

		return $c;
	}

	/**
	 * Look for a version constant or docblock tag in a library's own source.
	 *
	 * Scans a bounded number of files so a large tree cannot make this slow.
	 */
	private function find_version_constant( string $dir ): ?array {
		$patterns = array(
			// const VERSION = '19.0.0';
			'/\bconst\s+(?:VERSION|LIBRARY_VERSION|SDK_VERSION)\s*=\s*[\'"]([0-9][^\'"]*)[\'"]/i',
			// define( 'FOO_VERSION', '1.2.3' );
			'/define\s*\(\s*[\'"][A-Z0-9_]*VERSION[\'"]\s*,\s*[\'"]([0-9][^\'"]*)[\'"]/i',
			// @version 1.2.3
			'/@version\s+v?([0-9][0-9A-Za-z.\-+]*)/i',
		);

		$budget = 250;
		foreach ( $this->version_search_order( $dir ) as $file ) {
			if ( $budget-- <= 0 ) {
				break;
			}
			$head = (string) file_get_contents( $file, false, null, 0, 16384 );
			foreach ( $patterns as $pattern ) {
				if ( preg_match( $pattern, $head, $m ) ) {
					return array(
						'version' => trim( $m[1] ),
						'file'    => $this->rel( $file ),
					);
				}
			}
		}
		return null;
	}

	/**
	 * PHP files in the order most likely to carry the library's version.
	 *
	 * Order matters more than breadth here. A library the size of an API client
	 * has hundreds of files and the version lives in exactly one of them, almost
	 * always a shallow file named after the library itself. Walking in directory
	 * order finds several hundred namespace classes before reaching it.
	 */
	private function version_search_order( string $dir ): \Generator {
		$seen = array();
		$emit = function ( array $files ) use ( &$seen ) {
			foreach ( $files as $file ) {
				if ( is_file( $file ) && ! isset( $seen[ $file ] ) ) {
					$seen[ $file ] = true;
					yield $file;
				}
			}
		};

		$stem = strtolower( preg_replace( '/[^a-z0-9]+/i', '', basename( $dir ) ) );

		// 1. Shallow files, and files named after the library, which is where a
		//    version constant conventionally lives.
		yield from $emit( glob( $dir . '/*.php' ) ?: array() );

		foreach ( array( 'lib', 'src', 'includes', 'source' ) as $sub ) {
			$candidates = glob( $dir . '/' . $sub . '/*.php' ) ?: array();
			usort(
				$candidates,
				static function ( $a, $b ) use ( $stem ) {
					$score = static function ( $path ) use ( $stem ) {
						$base = strtolower( preg_replace( '/[^a-z0-9]+/i', '', basename( $path, '.php' ) ) );
						return ( '' !== $base && false !== strpos( $stem, $base ) ) ? 0 : 1;
					};
					return $score( $a ) <=> $score( $b );
				}
			);
			yield from $emit( $candidates );
		}

		// 2. Everything else, bounded by the caller's budget.
		foreach ( $this->walk( $dir ) as $file ) {
			if ( preg_match( '/\.php$/i', $file ) && ! isset( $seen[ $file ] ) ) {
				$seen[ $file ] = true;
				yield $file;
			}
		}
	}

	/** Read the first lines of a LICENSE file and name the licence if we can. */
	private function sniff_license_file( string $dir ): ?string {
		foreach ( array( 'LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING' ) as $candidate ) {
			$path = $dir . '/' . $candidate;
			if ( ! is_file( $path ) ) {
				continue;
			}
			$head = strtolower( (string) file_get_contents( $path, false, null, 0, 4096 ) );

			$map = array(
				'mit license'                        => 'MIT',
				'apache license'                     => 'Apache-2.0',
				'gnu general public license'         => 'GPL',
				'bsd 3-clause'                       => 'BSD-3-Clause',
				'bsd 2-clause'                       => 'BSD-2-Clause',
				'mozilla public license'             => 'MPL-2.0',
				'isc license'                        => 'ISC',
			);
			foreach ( $map as $needle => $spdx ) {
				if ( false !== strpos( $head, $needle ) ) {
					// Narrow the GPL to a version where the text says so.
					if ( 'GPL' === $spdx ) {
						if ( false !== strpos( $head, 'version 3' ) ) {
							return 'GPL-3.0';
						}
						if ( false !== strpos( $head, 'version 2' ) ) {
							return 'GPL-2.0';
						}
					}
					return $spdx;
				}
			}
			return null;
		}
		return null;
	}

	/* --------------------------------------------------------------------
	 * 5. Bundled front end assets
	 * ----------------------------------------------------------------- */

	private function detect_bundled_assets(): void {
		foreach ( $this->walk( $this->root ) as $file ) {
			if ( ! preg_match( '/\.(js|css)$/i', $file ) ) {
				continue;
			}
			if ( false !== strpos( $file, '/node_modules/' ) ) {
				continue;
			}

			$head = (string) file_get_contents( $file, false, null, 0, 4096 );
			$c    = $this->identify_asset( $head, $file );
			if ( null !== $c ) {
				$this->add( $c );
			}
		}
	}

	private function identify_asset( string $head, string $file ): ?Component {
		// jsDelivr rewrites are extremely common and name the package exactly.
		// e.g. Original file: /npm/canvas-confetti@1.5.1/dist/confetti.browser.js
		if ( preg_match( '#/npm/((?:@[^/@]+/)?[^/@]+)@([0-9][^/\s]*)#', $head, $m ) ) {
			$c             = new Component( $m[1] );
			$c->version    = $m[2];
			$c->confidence = IDENTIFIED;
			$c->purl       = 'pkg:npm/' . $m[1] . '@' . $m[2];
			$c->path       = $this->rel( $file );
			$c->evidence   = 'CDN banner in ' . basename( $file );
			return $c;
		}

		// Conventional preserved banner, which by convention opens the file and
		// starts with the bang: /*! jQuery v3.6.0 | (c) ...
		//
		// The bang and the start-of-file anchor both matter. Without them an
		// ordinary source comment such as "/* NEW in 10.15.0 */" reads as a
		// package called NEW, which is how this check failed the first time.
		if ( preg_match( '#^\s*/\*!\s*([A-Za-z][A-Za-z0-9._\-]{1,30}(?:[ ][A-Za-z0-9._\-]{1,20})?)[\s,|]+v?([0-9]+\.[0-9]+[0-9A-Za-z.\-+]*)#', $head, $m ) ) {
			$name = trim( $m[1] );
			if ( ! in_array( strtolower( $name ), self::BANNER_STOPWORDS, true ) ) {
				$c             = new Component( $name );
				$c->version    = $m[2];
				$c->confidence = IDENTIFIED;
				$c->path       = $this->rel( $file );
				$c->evidence   = 'preserved banner in ' . basename( $file );
				return $c;
			}
		}

		// Minified with no banner at all. This is only worth raising when it is
		// not the author's own build output, and the reliable signal for that is
		// whether an unminified source of the same name sits beside it.
		if ( preg_match( '/^(.*)\.min\.(js|css)$/i', $file, $m ) ) {
			if ( is_file( $m[1] . '.' . $m[2] ) ) {
				return null; // Built from a local source, so it is the author's own.
			}
			$c             = new Component( basename( $file ) );
			$c->confidence = UNIDENTIFIED;
			$c->path       = $this->rel( $file );
			$c->evidence   = 'minified asset with no banner and no local source, origin unknown';
			return $c;
		}

		return null;
	}

	/* --------------------------------------------------------------------
	 * 6. Shipping hygiene
	 * ----------------------------------------------------------------- */

	private function detect_shipping_hygiene(): void {
		if ( is_dir( $this->root . '/node_modules' ) ) {
			$this->note( 'node_modules is present in this tree. If it ships, every package in it is part of your product.' );
		}
		if ( is_dir( $this->root . '/.git' ) ) {
			$this->note( 'A .git directory is present. This looks like a working tree rather than a build. Point this tool at what you actually ship for an accurate answer.' );
		}
		foreach ( $this->components as $c ) {
			if ( SUSPICION === $c->scope ) {
				$this->note( sprintf( 'Test or build tooling found in shipped scope: %s. Confirm it is excluded from your release build.', $c->name ) );
			}
		}
	}

	/* --------------------------------------------------------------------
	 * Filesystem helpers
	 * ----------------------------------------------------------------- */

	/** Multi-package containers at the root or one level down, e.g. includes/vendor. */
	private function composer_style_vendor_dirs(): array {
		$found = array();
		$bases = array_merge( array( $this->root ), glob( $this->root . '/*', GLOB_ONLYDIR ) ?: array() );

		foreach ( $bases as $base ) {
			foreach ( self::VENDOR_DIRS as $name ) {
				$path = $base . '/' . $name;
				if ( is_dir( $path ) && ! $this->is_claimed( $path ) ) {
					$found[] = $path;
				}
			}
		}
		return array_unique( $found );
	}

	private function contains_php( string $dir ): bool {
		$budget = 200;
		foreach ( $this->walk( $dir ) as $file ) {
			if ( $budget-- <= 0 ) {
				return false;
			}
			if ( preg_match( '/\.php$/i', $file ) ) {
				return true;
			}
		}
		return false;
	}

	/** Find files by name within a bounded depth. */
	private function find_files( string $filename, int $max_depth ): array {
		$out = array();
		$dirs = array( array( $this->root, 0 ) );

		while ( $dirs ) {
			list( $dir, $depth ) = array_shift( $dirs );
			$candidate = $dir . '/' . $filename;
			if ( is_file( $candidate ) ) {
				$out[] = $candidate;
			}
			if ( $depth >= $max_depth ) {
				continue;
			}
			foreach ( glob( $dir . '/*', GLOB_ONLYDIR ) ?: array() as $sub ) {
				$base = basename( $sub );
				if ( in_array( $base, self::SKIP_DIRS, true ) || 'node_modules' === $base ) {
					continue;
				}
				$dirs[] = array( $sub, $depth + 1 );
			}
		}
		return $out;
	}

	/** Yield every file under a directory, skipping noise. */
	private function walk( string $dir ): \Generator {
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
				static function ( $current ) {
					return ! ( $current->isDir() && in_array( $current->getFilename(), self::SKIP_DIRS, true ) );
				}
			),
			\RecursiveIteratorIterator::LEAVES_ONLY
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				++$this->files_seen;
				yield $file->getPathname();
			}
		}
	}

	private function read_json( string $path ) {
		if ( ! is_file( $path ) ) {
			return null;
		}
		$data = json_decode( (string) file_get_contents( $path ), true );
		if ( null === $data && JSON_ERROR_NONE !== json_last_error() ) {
			$this->note( 'Could not parse ' . $this->rel( $path ) . ': ' . json_last_error_msg() );
			return null;
		}
		return $data;
	}
}

/* -------------------------------------------------------------------------
 * Output
 * ---------------------------------------------------------------------- */

final class CycloneDX {

	public static function render( array $result, string $subject ): string {
		$components = array();
		$root       = null;

		foreach ( $result['components'] as $c ) {
			if ( 'application' === $c->type && '.' === $c->path ) {
				$root = $c;
				continue;
			}
			$components[] = self::component( $c );
		}

		$bom = array(
			'bomFormat'    => 'CycloneDX',
			'specVersion'  => '1.6',
			'serialNumber' => 'urn:uuid:' . self::uuid4(),
			'version'      => 1,
			'metadata'     => array(
				'timestamp' => gmdate( 'Y-m-d\TH:i:s\Z' ),
				'tools'     => array(
					'components' => array(
						array(
							'type'    => 'application',
							'name'    => 'bodholdt-sbom',
							'version' => VERSION,
						),
					),
				),
				'component' => $root ? self::component( $root ) : array(
					'type' => 'application',
					'name' => $subject,
				),
			),
			'components'   => $components,
		);

		return json_encode( $bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
	}

	private static function component( Component $c ): array {
		$out = array(
			'type'    => $c->type,
			'name'    => $c->name,
			'version' => $c->version ?? 'unknown',
		);

		if ( $c->purl ) {
			$out['purl'] = $c->purl;
		}
		if ( $c->licenses ) {
			$out['licenses'] = array_map(
				static function ( $l ) {
					return array( 'license' => array( 'name' => $l ) );
				},
				$c->licenses
			);
		}

		// The honest metadata. A consumer of this document should be able to see
		// how sure we were and why, not just the happy path.
		$out['properties'] = array(
			array( 'name' => 'bodholdt:confidence', 'value' => $c->confidence ),
			array( 'name' => 'bodholdt:scope', 'value' => $c->scope ),
			array( 'name' => 'bodholdt:path', 'value' => $c->path ),
			array( 'name' => 'bodholdt:evidence', 'value' => $c->evidence ),
		);

		return $out;
	}

	private static function uuid4(): string {
		$data    = random_bytes( 16 );
		$data[6] = chr( ( ord( $data[6] ) & 0x0f ) | 0x40 );
		$data[8] = chr( ( ord( $data[8] ) & 0x3f ) | 0x80 );
		return vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split( bin2hex( $data ), 4 ) );
	}
}

final class TextReport {

	public static function render( array $result, string $subject ): string {
		$by_confidence = array( IDENTIFIED => array(), PARTIAL => array(), UNIDENTIFIED => array() );
		$dev           = array();
		$suspect       = array();

		foreach ( $result['components'] as $c ) {
			if ( 'application' === $c->type && '.' === $c->path ) {
				continue;
			}
			if ( SUSPICION === $c->scope ) {
				$suspect[] = $c;
				continue;
			}
			if ( DEV_ONLY === $c->scope ) {
				$dev[] = $c;
				continue;
			}
			$by_confidence[ $c->confidence ][] = $c;
		}

		$out  = "\n";
		$out .= "Bodholdt SBOM " . VERSION . "\n";
		$out .= "Subject: {$subject}\n";
		$out .= 'Scanned: ' . number_format( $result['files_seen'] ) . " files at " . gmdate( 'Y-m-d H:i:s' ) . " UTC\n";
		$out .= str_repeat( '=', 72 ) . "\n";

		$out .= self::section(
			'IDENTIFIED',
			'Name and version both known. These are the ones you can answer questions about.',
			$by_confidence[ IDENTIFIED ]
		);

		$out .= self::section(
			'PARTIALLY IDENTIFIED',
			'Found and named, but the version or the licence is missing. Each of these is a gap in what you can report.',
			$by_confidence[ PARTIAL ]
		);

		$out .= self::section(
			'NOT IDENTIFIED',
			'Third party code is present here and this tool could not attribute it. This is the list that matters. You cannot report a vulnerability in a component you cannot name.',
			$by_confidence[ UNIDENTIFIED ]
		);

		if ( $suspect ) {
			$out .= self::section(
				'PRESENT BUT PROBABLY SHOULD NOT SHIP',
				'Test or build tooling found in shipped scope.',
				$suspect
			);
		}

		if ( $dev ) {
			$out .= "\nBUILD TIME ONLY (" . count( $dev ) . ")\n";
			$out .= "  Not part of the shipped product, listed for completeness. Use --all to expand.\n";
		}

		if ( $result['notes'] ) {
			$out .= "\nNOTES\n";
			foreach ( $result['notes'] as $note ) {
				$out .= '  - ' . wordwrap( $note, 68, "\n    " ) . "\n";
			}
		}

		$total   = count( $by_confidence[ IDENTIFIED ] ) + count( $by_confidence[ PARTIAL ] ) + count( $by_confidence[ UNIDENTIFIED ] );
		$unknown = count( $by_confidence[ PARTIAL ] ) + count( $by_confidence[ UNIDENTIFIED ] );

		$out .= "\n" . str_repeat( '=', 72 ) . "\n";
		$out .= sprintf( "%d shipped components. %d fully identified, %d with gaps.\n", $total, count( $by_confidence[ IDENTIFIED ] ), $unknown );

		if ( $unknown > 0 ) {
			$out .= "\nThe gaps are the useful output. Every one of them is a component you\n";
			$out .= "would not be able to account for if somebody asked you what is in your\n";
			$out .= "product and whether it is affected by a given vulnerability.\n";
		}

		$out .= "\nThis tool reports what it can see in a directory. It is not legal advice\n";
		$out .= "and it does not tell you whether any obligation applies to you.\n";

		return $out;
	}

	private static function section( string $title, string $blurb, array $components ): string {
		$out = "\n" . $title . ' (' . count( $components ) . ")\n";
		if ( ! $components ) {
			return $out . "  None.\n";
		}
		$out .= '  ' . wordwrap( $blurb, 68, "\n  " ) . "\n\n";

		usort(
			$components,
			static function ( Component $a, Component $b ) {
				return strcasecmp( $a->name, $b->name );
			}
		);

		foreach ( $components as $c ) {
			$version = $c->version ?? '(no version found)';
			$license = $c->licenses ? implode( ', ', $c->licenses ) : '(no licence found)';
			$out    .= sprintf( "  %-34s %s\n", self::truncate( $c->name, 34 ), $version );
			$out    .= sprintf( "  %-34s %s\n", '', $license );
			$out    .= sprintf( "  %-34s %s\n", '', $c->path );
			$out    .= sprintf( "  %-34s %s\n\n", '', $c->evidence );
		}
		return $out;
	}

	private static function truncate( string $s, int $len ): string {
		return strlen( $s ) <= $len ? $s : substr( $s, 0, $len - 1 ) . '~';
	}
}

/* -------------------------------------------------------------------------
 * Diff
 * ---------------------------------------------------------------------- */

final class Diff {

	public static function render( string $old_path, string $new_path ): string {
		$old = self::load( $old_path );
		$new = self::load( $new_path );

		$added   = array_diff_key( $new, $old );
		$removed = array_diff_key( $old, $new );
		$changed = array();

		foreach ( $new as $name => $version ) {
			if ( isset( $old[ $name ] ) && $old[ $name ] !== $version ) {
				$changed[ $name ] = array( $old[ $name ], $version );
			}
		}

		$out  = "\nSBOM diff\n";
		$out .= '  from ' . basename( $old_path ) . "\n";
		$out .= '  to   ' . basename( $new_path ) . "\n";
		$out .= str_repeat( '=', 72 ) . "\n\n";

		foreach ( $changed as $name => $pair ) {
			$out .= sprintf( "  CHANGED  %-30s %s -> %s\n", $name, $pair[0], $pair[1] );
		}
		foreach ( $added as $name => $version ) {
			$out .= sprintf( "  ADDED    %-30s %s\n", $name, $version );
		}
		foreach ( $removed as $name => $version ) {
			$out .= sprintf( "  REMOVED  %-30s %s\n", $name, $version );
		}

		if ( ! $changed && ! $added && ! $removed ) {
			$out .= "  No component changes.\n";
		}

		$out .= sprintf( "\n%d changed, %d added, %d removed.\n", count( $changed ), count( $added ), count( $removed ) );
		return $out;
	}

	private static function load( string $path ): array {
		$data = json_decode( (string) file_get_contents( $path ), true );
		if ( ! is_array( $data ) ) {
			fwrite( STDERR, "Could not read {$path} as a CycloneDX document.\n" );
			exit( 2 );
		}
		$out = array();
		foreach ( (array) ( $data['components'] ?? array() ) as $c ) {
			if ( isset( $c['name'] ) ) {
				$out[ (string) $c['name'] ] = (string) ( $c['version'] ?? 'unknown' );
			}
		}
		return $out;
	}
}

/* -------------------------------------------------------------------------
 * CLI
 * ---------------------------------------------------------------------- */

function usage(): void {
	$version = VERSION;
	echo <<<TXT

Bodholdt SBOM {$version}
A software bill of materials for a WordPress plugin or theme.

USAGE
  bodholdt-sbom.php <directory> [options]
  bodholdt-sbom.php --diff <old.json> <new.json>

OPTIONS
  --format=text|cyclonedx   Output format. Default: text.
  --output=<file>           Write to a file instead of standard output.
  --diff <old> <new>        Compare two CycloneDX documents.
  --help                    This message.

EXAMPLES
  bodholdt-sbom.php ./my-plugin
  bodholdt-sbom.php ./my-plugin --format=cyclonedx --output=sbom.json
  bodholdt-sbom.php --diff sbom-1.4.0.json sbom-1.5.0.json

NOTE
  Point this at what you actually ship, not at your working tree. A working
  tree contains your build tooling and your build tooling is not part of
  your product.

  This tool reports what it can see in a directory. It is not legal advice
  and it does not tell you whether any obligation applies to you.


TXT;
}

function main( array $argv ): int {
	$args    = array_slice( $argv, 1 );
	$format  = 'text';
	$output  = null;
	$target  = null;
	$diff    = array();
	$in_diff = false;

	foreach ( $args as $arg ) {
		if ( '--help' === $arg || '-h' === $arg ) {
			usage();
			return 0;
		}
		if ( '--diff' === $arg ) {
			$in_diff = true;
			continue;
		}
		if ( 0 === strpos( $arg, '--format=' ) ) {
			$format = substr( $arg, 9 );
			continue;
		}
		if ( 0 === strpos( $arg, '--output=' ) ) {
			$output = substr( $arg, 9 );
			continue;
		}
		if ( 0 === strpos( $arg, '--' ) ) {
			fwrite( STDERR, "Unknown option: {$arg}\n" );
			return 2;
		}
		if ( $in_diff ) {
			$diff[] = $arg;
			continue;
		}
		$target = $arg;
	}

	if ( $in_diff ) {
		if ( 2 !== count( $diff ) ) {
			fwrite( STDERR, "--diff needs exactly two files.\n" );
			return 2;
		}
		$rendered = Diff::render( $diff[0], $diff[1] );
		return emit( $rendered, $output );
	}

	if ( null === $target ) {
		usage();
		return 2;
	}
	if ( ! is_dir( $target ) ) {
		fwrite( STDERR, "Not a directory: {$target}\n" );
		return 2;
	}
	if ( ! in_array( $format, array( 'text', 'cyclonedx' ), true ) ) {
		fwrite( STDERR, "Unknown format: {$format}\n" );
		return 2;
	}

	$scanner = new Scanner( $target );
	$result  = $scanner->scan();
	$subject = basename( realpath( $target ) ?: $target );

	$rendered = 'cyclonedx' === $format
		? CycloneDX::render( $result, $subject )
		: TextReport::render( $result, $subject );

	return emit( $rendered, $output );
}

function emit( string $content, ?string $output ): int {
	if ( null === $output ) {
		echo $content;
		return 0;
	}
	if ( false === file_put_contents( $output, $content ) ) {
		fwrite( STDERR, "Could not write to {$output}\n" );
		return 1;
	}
	fwrite( STDERR, "Written to {$output}\n" );
	return 0;
}

exit( main( $argv ) );
