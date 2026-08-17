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
 * TWO RULES GOVERN EVERY DETECTOR HERE, and they came out of a review that
 * found this file breaking both:
 *
 *   1. Never assert more than the evidence supports. A file that MENTIONS a
 *      package is not that package. A version found somewhere in a directory
 *      is not necessarily that directory's version. When two readings are
 *      possible, report neither and say so.
 *   2. Silence is a claim too. A directory this tool declined to examine must
 *      never be summarised as "no gaps". Being unable to identify something is
 *      a result, and it gets printed.
 *
 * Requires PHP 7.4 or later. No dependencies.
 *
 * @package BodholdtSBOM
 * @license GPL-2.0-or-later
 */

declare( strict_types = 1 );

namespace Bodholdt\SBOM;

const VERSION = '1.1.0';

// A document written to stdout must never have a PHP diagnostic interleaved
// into it. CLI PHP defaults display_errors to STDOUT, which would put a warning
// in the middle of the JSON and make it unparseable.
ini_set( 'display_errors', 'stderr' );

/* -------------------------------------------------------------------------
 * Component model
 * ---------------------------------------------------------------------- */

/**
 * How sure we are about a component.
 *
 * IDENTIFIED   name and version both established from authoritative evidence
 * PARTIAL      found and named, but something is inferred, missing or unverified
 * UNIDENTIFIED code is present and could not be attributed at all
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
		// Unattributed things have no version, so their key must include the
		// path or two different unknowns collapse into one and the count of
		// what could not be identified comes out short.
		if ( UNIDENTIFIED === $this->confidence || null === $this->version ) {
			return strtolower( $this->name ) . '@?|' . $this->path;
		}
		return strtolower( $this->name ) . '@' . $this->version;
	}
}

/* -------------------------------------------------------------------------
 * Scanner
 * ---------------------------------------------------------------------- */

final class Scanner {

	private const SKIP_DIRS = array( '.git', '.svn', '.hg', '.idea', '.vscode', '__MACOSX' );

	/**
	 * Directory names that conventionally hold several packages side by side.
	 *
	 * This list is now only a hint. Containers are also recognised structurally
	 * (see looks_like_package_container), because prefixing tools such as
	 * Strauss write to directory names that no fixed list can enumerate.
	 */
	private const VENDOR_DIRS = array( 'vendor', 'vendors', 'third-party', 'thirdparty', '3rdparty', 'external' );

	/** Places a WordPress plugin conventionally hides copied-in code. */
	private const CONTAINER_HINTS = array( 'includes', 'inc', 'lib', 'libs', 'library', 'libraries', 'src', 'app', 'core', 'modules', 'packages', 'dependencies' );

	/**
	 * Directory names that are conventionally the author's own furniture.
	 *
	 * Not evidence, just convention, so this only skips the directory as a
	 * LIBRARY candidate. Anything genuinely third party inside one is still
	 * reachable, because these are walked into rather than pruned.
	 */
	private const OWN_FURNITURE = array(
		'admin', 'assets', 'languages', 'templates', 'template', 'views', 'view',
		'partials', 'css', 'js', 'images', 'img', 'fonts', 'build', 'dist',
		'tests', 'test', 'docs', 'doc', 'bin', 'public', 'blocks', 'i18n',
	);

	/** Packages that are build or test tooling rather than product code. */
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
		'copyright', 'license', 'licence', 'generated', 'compiled', 'built', 'bundle',
		'do', 'this', 'the', 'for', 'and', 'all', 'part', 'based',
	);

	/**
	 * Constant name fragments that mean the number is NOT the package version.
	 *
	 * A schema version, a database revision or a minimum platform requirement
	 * all sit in constants ending in VERSION and are the wrong answer.
	 */
	private const NOT_A_PACKAGE_VERSION = array(
		'SCHEMA', 'DB_', '_DB', 'DATABASE', 'MIN', 'MINIMUM', 'REQUIRED', 'REQUIRE',
		'API_', 'PROTOCOL', 'WP_', 'PHP_', 'MYSQL', 'CACHE', 'ASSET', 'STORE',
		'MIGRATION', 'FORMAT', 'CONFIG', 'TESTED', 'SINCE',
	);

	/** How deep to look for copied-in libraries. Real plugins do not nest further. */
	private const MAX_CANDIDATE_DEPTH = 4;

	private string $root;
	private array $components = array();
	private array $notes      = array();
	private array $claimed    = array();
	private array $identity   = array();
	private array $stem_index = array();
	private bool $stem_built  = false;
	private int $files_seen   = 0;

	public function __construct( string $root ) {
		$this->root = rtrim( $root, '/' );
	}

	public function scan(): array {
		$this->derive_identity();

		// Containers are resolved BEFORE anything claims a subtree. A package
		// nested inside a library is a separate package, and computing this
		// afterwards let a claim hide it.
		$containers = $this->find_package_containers();

		$this->detect_root_component();
		$this->detect_composer( $containers );
		$this->detect_npm();
		$this->detect_vendored_php( $containers );
		$this->detect_single_file_libraries();
		$this->detect_bundled_assets();
		$this->detect_shipping_hygiene();

		return array(
			'components' => array_values( $this->components ),
			'notes'      => $this->notes,
			'files_seen' => $this->files_seen,
		);
	}

	private function add( Component $c ): void {
		$key = $c->key();

		if ( isset( $this->components[ $key ] ) ) {
			$existing = $this->components[ $key ];
			if ( $this->rank( $c->confidence ) <= $this->rank( $existing->confidence ) ) {
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
		if ( ! in_array( $message, $this->notes, true ) ) {
			$this->notes[] = $message;
		}
	}

	private function rel( string $path ): string {
		$rel = substr( $path, strlen( $this->root ) );
		return ltrim( $rel, '/' ) ?: '.';
	}

	/* --------------------------------------------------------------------
	 * Identity: telling the author's own code from everybody else's
	 * ----------------------------------------------------------------- */

	/**
	 * Collect the tokens that identify the product itself.
	 *
	 * Needed because the candidate test is no longer "does it carry a LICENSE".
	 * Casting a wider net means something has to keep the author's own
	 * subdirectories out of a report about third party code.
	 */
	private function derive_identity(): void {
		$tokens = $this->tokens( basename( $this->root ) );

		foreach ( glob( $this->esc( $this->root ) . '/*.php' ) ?: array() as $file ) {
			$head = $this->head( $file, 8192 );
			if ( preg_match( '/^[\s\*\/#@]*Plugin Name\s*:\s*(.+)$/mi', $head, $m ) ) {
				$tokens = array_merge( $tokens, $this->tokens( $m[1] ) );
			}
			if ( preg_match( '/^[\s\*\/#@]*Text Domain\s*:\s*(.+)$/mi', $head, $m ) ) {
				$tokens = array_merge( $tokens, $this->tokens( $m[1] ) );
			}
			if ( preg_match( '/^\s*namespace\s+([A-Za-z0-9_\\\\]+)/mi', $head, $m ) ) {
				$tokens = array_merge( $tokens, $this->tokens( $m[1] ) );
			}
		}

		$style = $this->root . '/style.css';
		if ( is_file( $style ) && preg_match( '/^[\s\*\/#@]*Theme Name\s*:\s*(.+)$/mi', $this->head( $style, 8192 ), $m ) ) {
			$tokens = array_merge( $tokens, $this->tokens( $m[1] ) );
		}

		// Single letters and very common words identify nothing.
		$tokens = array_filter(
			array_unique( $tokens ),
			static function ( $t ) {
				return strlen( $t ) >= 4 && ! in_array( $t, array( 'press', 'wordpress', 'plugin', 'theme', 'includes', 'assets' ), true );
			}
		);

		$this->identity = array_values( $tokens );
	}

	/**
	 * Break a name into comparable tokens, splitting CamelCase as well as
	 * punctuation.
	 *
	 * Without the CamelCase split, a class called BodholdtGDrive_Licensing
	 * yields the single token "bodholdtgdrive", which does not match the
	 * product's own "bodholdt", so the author's own file reads as foreign.
	 */
	private function tokens( string $text ): array {
		$split = preg_split( '/(?<=[a-z0-9])(?=[A-Z])|[^A-Za-z0-9]+/', $text ) ?: array();
		$out   = array();
		foreach ( $split as $part ) {
			$part = strtolower( trim( $part ) );
			if ( '' !== $part ) {
				$out[] = $part;
			}
		}
		return $out;
	}

	/**
	 * Does this directory's PHP positively look like somebody else's?
	 *
	 * Requires evidence FOR foreignness, never merely the absence of evidence
	 * for ownership. A directory of bare template files declares no namespace
	 * and no class, and reading that silence as "third party" reported admin/,
	 * assets/ and languages/ as unattributed dependencies. A copied-in library
	 * essentially always declares classes; a folder of partials does not.
	 */
	private function looks_third_party( string $dir ): bool {
		$budget = 8;
		$found  = array();

		foreach ( $this->php_files_shallow( $dir, 2 ) as $file ) {
			if ( $budget-- <= 0 ) {
				break;
			}
			$head = $this->head( $file, 8192 );
			if ( preg_match( '/^\s*namespace\s+([A-Za-z0-9_\\\\]+)/mi', $head, $m ) ) {
				$found = array_merge( $found, $this->tokens( $m[1] ) );
			}
			if ( preg_match_all( '/^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+([A-Za-z0-9_]+)/mi', $head, $m ) ) {
				foreach ( $m[1] as $class ) {
					$found = array_merge( $found, $this->tokens( $class ) );
				}
			}
			if ( preg_match( '/@package\s+([A-Za-z0-9_\\\\\-]+)/i', $head, $m ) ) {
				$found = array_merge( $found, $this->tokens( $m[1] ) );
			}
		}

		$found = array_unique( $found );

		// No declarations at all is not evidence of anything. Say no.
		if ( ! $found ) {
			return false;
		}
		// Declares names, and none of them are ours.
		return ! array_intersect( $this->identity, $found );
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
					'license'  => $this->first_license( $composer['license'] ?? null ),
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

	private function read_plugin_header(): ?array {
		$headers = array();

		foreach ( glob( $this->esc( $this->root ) . '/*.php' ) ?: array() as $file ) {
			$head = $this->head( $file, 8192 );
			if ( ! preg_match( '/^[\s\*\/#@]*Plugin Name\s*:\s*(.+)$/mi', $head, $m ) ) {
				continue;
			}
			$headers[] = array(
				'name'     => trim( $m[1] ),
				'version'  => preg_match( '/^[\s\*\/#@]*Version\s*:\s*(.+)$/mi', $head, $v ) ? trim( $v[1] ) : null,
				'license'  => preg_match( '/^[\s\*\/#@]*License\s*:\s*(.+)$/mi', $head, $l ) ? trim( $l[1] ) : null,
				'evidence' => 'plugin header in ' . basename( $file ),
				'file'     => $file,
			);
		}

		if ( ! $headers ) {
			return null;
		}

		if ( count( $headers ) > 1 ) {
			// glob() is alphabetical, and '-' sorts before '.', so a file such
			// as my-plugin-legacy.php would silently beat my-plugin.php and
			// become the subject of the whole document.
			$names = array();
			foreach ( $headers as $h ) {
				$names[] = basename( $h['file'] );
			}
			$this->note(
				sprintf(
					'More than one file at the top level declares a Plugin Name (%s). This report describes "%s" from %s. If that is the wrong one, point the tool at the right directory or check for a stray file.',
					implode( ', ', $names ),
					$headers[0]['name'],
					basename( $headers[0]['file'] )
				)
			);
		}

		return $headers[0];
	}

	private function read_theme_header(): ?array {
		$style = $this->root . '/style.css';
		if ( ! is_file( $style ) ) {
			return null;
		}
		$head = $this->head( $style, 8192 );
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

	private function detect_composer( array $containers ): void {
		foreach ( $containers as $vendor_dir ) {
			$installed = $this->read_json( $vendor_dir . '/composer/installed.json' );
			if ( ! is_array( $installed ) ) {
				continue;
			}

			$packages = isset( $installed['packages'] ) ? (array) $installed['packages'] : $installed;

			// installed.json states which packages are dev-only. Believe it,
			// rather than inferring dev scope from a hardcoded name list.
			$dev_names = array();
			foreach ( (array) ( $installed['dev-package-names'] ?? array() ) as $n ) {
				$dev_names[ strtolower( (string) $n ) ] = true;
			}

			foreach ( $packages as $pkg ) {
				if ( ! is_array( $pkg ) || ! isset( $pkg['name'] ) ) {
					continue;
				}
				$name  = (string) $pkg['name'];
				$lower = strtolower( $name );

				$c             = new Component( $name );
				$c->version    = isset( $pkg['version'] ) ? (string) $pkg['version'] : null;
				$c->licenses   = $this->licenses_of( $pkg['license'] ?? null );
				$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
				$c->path       = $this->rel( $vendor_dir );
				$c->purl       = $c->version ? 'pkg:composer/' . $name . '@' . $c->version : null;
				$c->evidence   = 'vendor/composer/installed.json';

				if ( isset( $dev_names[ $lower ] ) ) {
					$c->scope = DEV_ONLY;
				} elseif ( in_array( $lower, self::DEV_TOOLING, true ) ) {
					$c->scope = SUSPICION;
				}

				$this->add( $c );

				// Claim the package's own directory, not the whole vendor
				// container. Claiming the container hid every library in that
				// tree that installed.json did not happen to mention.
				$pkg_dir = $vendor_dir . '/' . $name;
				if ( is_dir( $pkg_dir ) ) {
					$this->claimed[] = $pkg_dir;
				}
			}
		}

		foreach ( $this->find_files( 'composer.lock', 4 ) as $lock_path ) {
			// A lockfile inside a vendor directory belongs to a dependency and
			// describes ITS dependencies, not this product's.
			if ( preg_match( '#/(vendor|vendor-prefixed|node_modules)/#', $lock_path ) ) {
				continue;
			}
			$lock = $this->read_json( $lock_path );
			if ( ! is_array( $lock ) ) {
				continue;
			}
			$dir = $this->rel( dirname( $lock_path ) );

			foreach ( array( 'packages' => SHIPPED, 'packages-dev' => DEV_ONLY ) as $section => $scope ) {
				foreach ( (array) ( $lock[ $section ] ?? array() ) as $pkg ) {
					if ( ! is_array( $pkg ) || ! isset( $pkg['name'] ) ) {
						continue;
					}
					$name          = (string) $pkg['name'];
					$c             = new Component( $name );
					$c->version    = isset( $pkg['version'] ) ? (string) $pkg['version'] : null;
					$c->licenses   = $this->licenses_of( $pkg['license'] ?? null );
					$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
					$c->scope      = $scope;
					$c->path       = $dir;
					$c->purl       = $c->version ? 'pkg:composer/' . $name . '@' . $c->version : null;
					$c->evidence   = 'composer.lock (' . $section . ')';

					if ( SHIPPED === $scope && in_array( strtolower( $name ), self::DEV_TOOLING, true ) ) {
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
			$dir   = $this->rel( dirname( $lock_path ) );
			$ships = is_dir( dirname( $lock_path ) . '/node_modules' );

			if ( ! $ships ) {
				$this->note(
					sprintf(
						'%s: node dependencies are recorded but node_modules is not present. Entries the lockfile marks as dev are reported as build time only; the rest are reported by what the lockfile says, not by what ships. If your build inlines them into a shipped bundle, they are part of your product and this tool cannot see that.',
						$dir
					)
				);
			}

			$packages = (array) ( $lock['packages'] ?? array() );
			if ( $packages ) {
				foreach ( $packages as $rel_path => $pkg ) {
					if ( '' === $rel_path || ! is_array( $pkg ) ) {
						continue; // The empty key is the project itself.
					}
					// A "link" entry is a workspace alias, not a package.
					if ( ! empty( $pkg['link'] ) ) {
						continue;
					}
					// Only node_modules paths name a real installed package.
					// Workspace paths are directories and must not become purls.
					if ( false === strpos( (string) $rel_path, 'node_modules/' ) && ! isset( $pkg['name'] ) ) {
						continue;
					}

					$name = isset( $pkg['name'] )
						? (string) $pkg['name']
						: (string) preg_replace( '#^.*node_modules/#', '', (string) $rel_path );
					if ( '' === $name ) {
						continue;
					}

					$c             = new Component( $name );
					$c->version    = isset( $pkg['version'] ) ? (string) $pkg['version'] : null;
					$c->licenses   = $this->licenses_of( $pkg['license'] ?? null );
					$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
					$c->scope      = empty( $pkg['dev'] ) ? SHIPPED : DEV_ONLY;
					$c->path       = $dir;
					$c->purl       = $c->version ? $this->npm_purl( $name, $c->version ) : null;
					$c->evidence   = 'package-lock.json';
					$this->add( $c );
				}
			} else {
				foreach ( (array) ( $lock['dependencies'] ?? array() ) as $name => $pkg ) {
					if ( ! is_array( $pkg ) ) {
						continue;
					}
					$c             = new Component( (string) $name );
					$c->version    = isset( $pkg['version'] ) ? (string) $pkg['version'] : null;
					$c->confidence = $c->version ? IDENTIFIED : PARTIAL;
					$c->scope      = empty( $pkg['dev'] ) ? SHIPPED : DEV_ONLY;
					$c->path       = $dir;
					$c->purl       = $c->version ? $this->npm_purl( (string) $name, $c->version ) : null;
					$c->evidence   = 'package-lock.json (v1)';
					$this->add( $c );
				}
			}
		}
	}

	/** A scoped npm package's leading @ is percent encoded in a canonical purl. */
	private function npm_purl( string $name, string $version ): string {
		if ( 0 === strpos( $name, '@' ) ) {
			$name = '%40' . substr( $name, 1 );
		}
		return 'pkg:npm/' . $name . '@' . $version;
	}

	/* --------------------------------------------------------------------
	 * 4. Copied-in PHP, the part that matters
	 * ----------------------------------------------------------------- */

	/**
	 * Find directories that hold several packages side by side.
	 *
	 * Recognised by name for the conventional ones, and structurally for the
	 * rest: a directory whose grandchildren carry manifests is a container
	 * whatever it is called. Prefixing tools write to names no list can guess.
	 */
	private function find_package_containers(): array {
		$found = array();

		foreach ( $this->directories( self::MAX_CANDIDATE_DEPTH ) as $dir ) {
			$name = strtolower( basename( $dir ) );

			if ( in_array( $name, self::VENDOR_DIRS, true ) ) {
				$found[] = $dir;
				continue;
			}
			if ( $this->looks_like_package_container( $dir ) ) {
				$found[] = $dir;
			}
		}

		// A root composer.json can name a prefixing tool's target directory.
		$composer = $this->read_json( $this->root . '/composer.json' );
		foreach ( array( 'strauss', 'mozart' ) as $tool ) {
			$target = $composer['extra'][ $tool ]['target_directory'] ?? ( $composer['extra'][ $tool ]['dep_directory'] ?? null );
			if ( is_string( $target ) ) {
				$path = $this->root . '/' . trim( $target, '/' );
				if ( is_dir( $path ) ) {
					$found[] = $path;
				}
			}
		}

		return array_values( array_unique( $found ) );
	}

	/** publisher/package/composer.json is the composer layout, whatever the top dir is called. */
	private function looks_like_package_container( string $dir ): bool {
		if ( is_file( $dir . '/composer/installed.json' ) ) {
			return true;
		}
		$hits = 0;
		foreach ( glob( $this->esc( $dir ) . '/*', GLOB_ONLYDIR ) ?: array() as $publisher ) {
			foreach ( glob( $this->esc( $publisher ) . '/*', GLOB_ONLYDIR ) ?: array() as $pkg ) {
				if ( is_file( $pkg . '/composer.json' ) || $this->has_license_file( $pkg ) ) {
					++$hits;
					if ( $hits >= 2 ) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private function detect_vendored_php( array $containers ): void {
		// Pass A: packages inside a container. Children there really are
		// separate packages, so this runs first and claims them individually.
		foreach ( $containers as $container ) {
			foreach ( glob( $this->esc( $container ) . '/*', GLOB_ONLYDIR ) ?: array() as $publisher ) {
				$packages = glob( $this->esc( $publisher ) . '/*', GLOB_ONLYDIR ) ?: array();
				foreach ( $packages ?: array( $publisher ) as $pkg_dir ) {
					if ( $this->is_claimed( $pkg_dir ) ) {
						continue;
					}
					$php = $this->contains_php( $pkg_dir );
					if ( 'no' === $php ) {
						continue;
					}
					$this->add( $this->identify_vendored_library( $pkg_dir, 'unknown' === $php ) );
					$this->claimed[] = $pkg_dir;
				}
			}
		}

		// Pass B: a whole library copied in somewhere else in the tree. No
		// longer gated on carrying a LICENSE, because a library whose
		// attribution was stripped is exactly what this tool exists to find.
		foreach ( $this->directories( self::MAX_CANDIDATE_DEPTH ) as $dir ) {
			if ( $this->is_claimed( $dir ) || $this->inside_container( $dir, $containers ) ) {
				continue;
			}
			$name = strtolower( basename( $dir ) );
			if ( in_array( $name, self::SKIP_DIRS, true ) || 'node_modules' === $name ) {
				continue;
			}
			// Conventional container names are places to look, not libraries.
			// Conventional furniture names are the author's own, unless they
			// carry a manifest saying otherwise.
			if ( in_array( $name, self::CONTAINER_HINTS, true ) || in_array( $name, self::VENDOR_DIRS, true ) ) {
				continue;
			}
			if ( in_array( $name, self::OWN_FURNITURE, true )
				&& ! $this->has_license_file( $dir ) && ! is_file( $dir . '/composer.json' ) ) {
				continue;
			}

			$php = $this->contains_php( $dir );
			if ( 'no' === $php ) {
				continue;
			}

			// A pass-through directory is not the library. Descend to the
			// shallowest directory that actually holds the code, so the report
			// names "nested-lib" rather than the folder it happens to sit in.
			$dir = $this->narrow_to_library( $dir );
			if ( $this->is_claimed( $dir ) ) {
				continue;
			}

			$has_manifest = $this->has_license_file( $dir ) || is_file( $dir . '/composer.json' );

			// Without a manifest, the only thing separating a copied-in library
			// from one of the author's own directories is whose names are in
			// the code. Getting this wrong in one direction invents a
			// dependency; in the other it hides one. So a manifest admits it
			// outright, and otherwise it needs positive evidence of being
			// somebody else's.
			if ( ! $has_manifest && ! $this->looks_third_party( $dir ) ) {
				continue;
			}

			$this->add( $this->identify_vendored_library( $dir, 'unknown' === $php ) );
			$this->claimed[] = $dir;
		}
	}

	/**
	 * Walk down through pass-through directories to the actual library.
	 *
	 * `inc/deep/nested-lib` should be reported as nested-lib, not as the
	 * intermediate folder that merely contains it. Stops as soon as a
	 * directory holds PHP of its own, carries a manifest, or branches.
	 */
	private function narrow_to_library( string $dir ): string {
		$guard = 0;
		while ( $guard++ < self::MAX_CANDIDATE_DEPTH ) {
			if ( glob( $this->esc( $dir ) . '/*.php' ) || $this->has_license_file( $dir ) || is_file( $dir . '/composer.json' ) ) {
				return $dir;
			}
			$children = glob( $this->esc( $dir ) . '/*', GLOB_ONLYDIR ) ?: array();
			if ( 1 !== count( $children ) ) {
				return $dir;
			}
			$dir = $children[0];
		}
		return $dir;
	}

	private function inside_container( string $dir, array $containers ): bool {
		foreach ( $containers as $container ) {
			if ( 0 === strpos( $dir, $container . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Work out what a copied-in library is, from whatever evidence exists.
	 *
	 * Confidence is the WEAKER of the name evidence and the version evidence.
	 * A name from a manifest plus a version guessed out of a source file is
	 * not "name and version both known", and filing it that way was telling
	 * the reader they could answer questions they could not answer.
	 */
	private function identify_vendored_library( string $dir, bool $truncated = false ): Component {
		$c        = new Component( basename( $dir ) );
		$c->path  = $this->rel( $dir );
		$c->scope = SHIPPED;

		$named_by_manifest = false;
		$composer          = $this->read_json( $dir . '/composer.json' );

		if ( is_array( $composer ) && isset( $composer['name'] ) ) {
			$named_by_manifest = true;
			$c->name           = (string) $composer['name'];
			$c->licenses       = $this->licenses_of( $composer['license'] ?? null );
			if ( isset( $composer['version'] ) ) {
				$c->version    = (string) $composer['version'];
				$c->confidence = IDENTIFIED;
				$c->evidence   = 'vendored, name and version from its own composer.json';
			} else {
				$c->confidence = PARTIAL;
				$c->evidence   = 'vendored, name from its own composer.json, no version declared';
			}
		}

		if ( null === $c->version ) {
			$found = $this->find_version( $dir );
			if ( isset( $found['conflict'] ) ) {
				$c->confidence = PARTIAL;
				$c->evidence   = 'vendored, ' . ( $named_by_manifest ? 'name from composer.json, ' : '' )
					. 'no version recorded because more than one candidate was found ('
					. $found['conflict'] . ')';
				$this->note(
					sprintf(
						'%s: found more than one possible version (%s), so none is recorded. Check it by hand.',
						$c->path,
						$found['conflict']
					)
				);
			} elseif ( null !== $found ) {
				$c->version    = $found['version'];
				$c->confidence = PARTIAL; // Inferred, never authoritative.
				$c->evidence   = 'vendored, ' . ( $named_by_manifest ? 'name from composer.json, ' : '' )
					. 'version inferred from ' . $found['file'] . ', unverified';
			}
		}

		if ( ! $c->licenses ) {
			$license = $this->sniff_license_file( $dir, $c->path );
			if ( null !== $license ) {
				$c->licenses = array( $license );
			}
		}

		if ( '' === $c->evidence ) {
			$c->evidence   = 'code present here that could not be attributed to a known package';
			$c->confidence = UNIDENTIFIED;
		}

		if ( $truncated ) {
			$c->evidence .= '; the scan of this directory was truncated';
			$this->note( $c->path . ': too large to examine fully, so this entry may be incomplete.' );
		}

		return $c;
	}

	/**
	 * A single .php file dropped in as a library.
	 *
	 * Every other detector requires a directory, which excludes the whole class
	 * of one-file drop-ins even when the file states its own version.
	 */
	private function detect_single_file_libraries(): void {
		foreach ( glob( $this->esc( $this->root ) . '/*.php' ) ?: array() as $file ) {
			$head = $this->head( $file, 16384 );

			// The main plugin file is the subject, not a dependency.
			if ( preg_match( '/^[\s\*\/#@]*Plugin Name\s*:/mi', $head ) ) {
				continue;
			}
			// A file whose own names match the product is the author's own.
			$own = array();
			if ( preg_match( '/^\s*namespace\s+([A-Za-z0-9_\\\\]+)/mi', $head, $m ) ) {
				$own = array_merge( $own, $this->tokens( $m[1] ) );
			}
			if ( preg_match_all( '/^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+([A-Za-z0-9_]+)/mi', $head, $m ) ) {
				foreach ( $m[1] as $class ) {
					$own = array_merge( $own, $this->tokens( $class ) );
				}
			}
			if ( ! $own || array_intersect( $this->identity, $own ) ) {
				continue;
			}

			$version = $this->version_from_source( $head, true );
			$c       = new Component( basename( $file, '.php' ) );
			$c->path = $this->rel( $file );

			if ( null !== $version && ! isset( $version['conflict'] ) ) {
				$c->version    = $version['version'];
				$c->confidence = PARTIAL;
				$c->evidence   = 'single file library, version inferred from its own source, unverified';
			} else {
				$c->confidence = UNIDENTIFIED;
				$c->evidence   = 'single PHP file that declares names unrelated to this product';
			}
			$this->add( $c );
		}
	}

	/* --------------------------------------------------------------------
	 * Version inference
	 * ----------------------------------------------------------------- */

	/**
	 * Find a library's version, or decline to.
	 *
	 * Evidence is tiered. A `const VERSION` in the library's own source is
	 * strong; a define() is weaker; an @version docblock is weakest and is only
	 * trusted in a file that looks like the library's entry point. Within the
	 * strongest tier that produced anything, a single distinct value wins and
	 * two competing values produce nothing at all, because picking one is how
	 * a real package name ends up carrying a schema revision as its version.
	 */
	private function find_version( string $dir ): ?array {
		$stem   = $this->stem( basename( $dir ) );
		$tiers  = array( 1 => array(), 2 => array(), 3 => array() );
		$budget = 250;

		foreach ( $this->version_search_order( $dir ) as $file ) {
			if ( $budget-- <= 0 ) {
				break;
			}
			$head    = $this->head( $file, 16384 );
			$is_main = '' !== $stem && false !== strpos( $stem, $this->stem( basename( $file, '.php' ) ) );
			$found   = $this->version_from_source( $head, $is_main || false !== strpos( $head, '@package' ) );

			if ( null === $found || isset( $found['conflict'] ) ) {
				continue;
			}
			$tiers[ $found['tier'] ][ $found['version'] ] = $this->rel( $file );
		}

		foreach ( array( 1, 2, 3 ) as $tier ) {
			if ( ! $tiers[ $tier ] ) {
				continue;
			}
			if ( count( $tiers[ $tier ] ) > 1 ) {
				return array( 'conflict' => implode( ', ', array_keys( $tiers[ $tier ] ) ) );
			}
			$version = (string) array_key_first( $tiers[ $tier ] );
			return array( 'version' => $version, 'file' => $tiers[ $tier ][ $version ] );
		}

		return null;
	}

	/**
	 * Pull a version out of one file's source, with its evidence tier.
	 *
	 * @param bool $trust_docblock Whether an @version tag in this file is
	 *                             believable, which it only is in a file that
	 *                             looks like the library's entry point.
	 */
	private function version_from_source( string $head, bool $trust_docblock ) {
		// Tier 1: an explicit library version constant.
		if ( preg_match( '/\bconst\s+(?:VERSION|LIBRARY_VERSION|SDK_VERSION)\s*=\s*[\'"]([0-9][^\'"]*)[\'"]/i', $head, $m ) ) {
			return array( 'version' => trim( $m[1] ), 'tier' => 1 );
		}

		// Tier 2: a define() whose constant name is plausibly the package's own
		// version, and is not a schema revision or a platform requirement.
		if ( preg_match_all( '/define\s*\(\s*[\'"]([A-Za-z0-9_]*VERSION)[\'"]\s*,\s*[\'"]([0-9][^\'"]*)[\'"]/i', $head, $all, PREG_SET_ORDER ) ) {
			$candidates = array();
			foreach ( $all as $m ) {
				if ( $this->is_package_version_constant( $m[1] ) ) {
					$candidates[ trim( $m[2] ) ] = true;
				}
			}
			if ( count( $candidates ) > 1 ) {
				return array( 'conflict' => implode( ', ', array_keys( $candidates ) ) );
			}
			if ( 1 === count( $candidates ) ) {
				return array( 'version' => (string) array_key_first( $candidates ), 'tier' => 2 );
			}
		}

		// Tier 3: an @version docblock, only where the file looks like an entry point.
		if ( $trust_docblock && preg_match( '/@version\s+v?([0-9][0-9A-Za-z.\-+]*)/i', $head, $m ) ) {
			return array( 'version' => trim( $m[1] ), 'tier' => 3 );
		}

		return null;
	}

	private function is_package_version_constant( string $name ): bool {
		$upper = strtoupper( $name );
		if ( ! preg_match( '/^[A-Z0-9_]*_?VERSION$/', $upper ) ) {
			return false;
		}
		foreach ( self::NOT_A_PACKAGE_VERSION as $reject ) {
			if ( false !== strpos( $upper, $reject ) ) {
				return false;
			}
		}
		return true;
	}

	private function stem( string $name ): string {
		return strtolower( (string) preg_replace( '/[^a-z0-9]+/i', '', $name ) );
	}

	/**
	 * PHP files in the order most likely to carry the library's version.
	 *
	 * Ordering matters more than breadth. A library the size of an API client
	 * has hundreds of files and the version lives in one of them, almost always
	 * a shallow file named after the library.
	 */
	private function version_search_order( string $dir ): \Generator {
		$seen = array();
		$stem = $this->stem( basename( $dir ) );

		$sorter = static function ( array $files ) use ( $stem ) {
			usort(
				$files,
				static function ( $a, $b ) use ( $stem ) {
					$score = static function ( $path ) use ( $stem ) {
						$base = strtolower( (string) preg_replace( '/[^a-z0-9]+/i', '', basename( $path, '.php' ) ) );
						if ( '' !== $base && '' !== $stem && false !== strpos( $stem, $base ) ) {
							return 0;
						}
						return in_array( strtolower( basename( $path ) ), array( 'init.php', 'bootstrap.php', 'autoload.php' ), true ) ? 1 : 2;
					};
					return $score( $a ) <=> $score( $b );
				}
			);
			return $files;
		};

		// Shallow files first, name-scored. The scoring used to be applied only
		// to lib/src/includes, so a plain alphabetical glob of the root decided
		// the answer and barcodes.php beat tcpdf.php.
		foreach ( $sorter( glob( $this->esc( $dir ) . '/*.php' ) ?: array() ) as $file ) {
			if ( ! isset( $seen[ $file ] ) ) {
				$seen[ $file ] = true;
				yield $file;
			}
		}

		foreach ( array( 'lib', 'src', 'includes', 'source' ) as $sub ) {
			foreach ( $sorter( glob( $this->esc( $dir . '/' . $sub ) . '/*.php' ) ?: array() ) as $file ) {
				if ( ! isset( $seen[ $file ] ) ) {
					$seen[ $file ] = true;
					yield $file;
				}
			}
		}

		foreach ( $this->walk( $dir ) as $file ) {
			if ( preg_match( '/\.php$/i', $file ) && ! isset( $seen[ $file ] ) ) {
				$seen[ $file ] = true;
				yield $file;
			}
		}
	}

	/* --------------------------------------------------------------------
	 * Licences
	 * ----------------------------------------------------------------- */

	/** Normalise a manifest licence value, which may be a string, a list or a map. */
	private function licenses_of( $raw ): array {
		if ( null === $raw ) {
			return array();
		}
		$out = array();
		foreach ( (array) $raw as $value ) {
			if ( is_scalar( $value ) ) {
				$value = trim( (string) $value );
				if ( '' !== $value ) {
					$out[] = $value;
				}
			}
		}
		return array_values( array_unique( $out ) );
	}

	private function first_license( $raw ): ?string {
		$all = $this->licenses_of( $raw );
		return $all ? $all[0] : null;
	}

	/**
	 * Name the licence in a LICENSE file, or decline to.
	 *
	 * LGPL and AGPL both contain the phrase "GNU General Public License", so a
	 * plain substring test calls them GPL, which is a materially wrong answer
	 * about somebody's obligations. The specific families are tested first, and
	 * a file naming more than one family produces nothing.
	 */
	private function sniff_license_file( string $dir, string $rel ): ?string {
		foreach ( array( 'LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING', 'LICENCE' ) as $candidate ) {
			$path = $dir . '/' . $candidate;
			if ( ! is_file( $path ) ) {
				continue;
			}
			$text = strtolower( $this->head( $path, 8192 ) );

			$families = array();
			if ( false !== strpos( $text, 'gnu lesser general public license' ) ) {
				$families['LGPL'] = true;
			}
			if ( false !== strpos( $text, 'gnu affero general public license' ) ) {
				$families['AGPL'] = true;
			}
			// Only plain GPL if the phrase appears without lesser/affero in front.
			if ( preg_match( '/(?<!lesser )(?<!affero )gnu general public license/', $text ) ) {
				$families['GPL'] = true;
			}
			foreach ( array(
				'MIT'          => 'mit license',
				'Apache-2.0'   => 'apache license',
				'BSD-3-Clause' => 'bsd 3-clause',
				'BSD-2-Clause' => 'bsd 2-clause',
				'MPL-2.0'      => 'mozilla public license',
				'ISC'          => 'isc license',
			) as $spdx => $needle ) {
				if ( false !== strpos( $text, $needle ) ) {
					$families[ $spdx ] = true;
				}
			}

			if ( ! $families ) {
				return null;
			}
			if ( count( $families ) > 1 ) {
				$this->note(
					sprintf( '%s: its %s names more than one licence (%s), so none is recorded. Read it yourself.', $rel, $candidate, implode( ', ', array_keys( $families ) ) )
				);
				return null;
			}

			$family = (string) array_key_first( $families );
			if ( in_array( $family, array( 'GPL', 'LGPL', 'AGPL' ), true ) ) {
				$version = false !== strpos( $text, 'version 3' ) ? '3.0' : ( false !== strpos( $text, 'version 2.1' ) ? '2.1' : ( false !== strpos( $text, 'version 2' ) ? '2.0' : null ) );
				if ( null === $version ) {
					return $family;
				}
				$later = false !== strpos( $text, 'any later version' );
				return $family . '-' . $version . ( $later ? '-or-later' : '-only' );
			}
			return $family;
		}
		return null;
	}

	/* --------------------------------------------------------------------
	 * Bundled front end assets
	 * ----------------------------------------------------------------- */

	private function detect_bundled_assets(): void {
		foreach ( $this->walk( $this->root ) as $file ) {
			if ( ! preg_match( '/\.(js|css)$/i', $file ) ) {
				continue;
			}
			if ( false !== strpos( $file, '/node_modules/' ) ) {
				continue;
			}
			// Assets belonging to a package already reported are that package's.
			if ( $this->is_claimed( dirname( $file ) ) ) {
				continue;
			}

			$head = $this->head( $file, 4096 );
			$c    = $this->identify_asset( $head, $file );
			if ( null !== $c ) {
				$this->add( $c );
			}
		}
	}

	private function identify_asset( string $head, string $file ): ?Component {
		$leading = $this->leading_comment( $head );

		// A CDN URL that is not part of a rewrite header is a reference, not an
		// identity. Record it as a note first, so the information survives
		// whichever branch below returns.
		if ( false === strpos( $leading, 'Original file:' )
			&& preg_match( '#/npm/((?:@[^/@\s]+/)?[^/@\s]+)@([0-9][0-9A-Za-z.\-+]*)#', $head, $ref ) ) {
			$this->note(
				sprintf(
					'%s mentions %s@%s from a CDN. That is a reference, not proof the code is in this file, so it is not listed as a component. Check whether it is loaded at runtime.',
					$this->rel( $file ),
					$ref[1],
					$ref[2]
				)
			);
		}

		// A conventional preserved banner opens the file and is the strongest
		// evidence available. It is tested FIRST: a CDN reference further down
		// the same file used to override it and erase the real package.
		if ( '' !== $leading && preg_match( '#^\s*/\*!\s*([A-Za-z][A-Za-z0-9._\-]{1,30}(?:[ ][A-Za-z0-9._\-]{1,20})?)[\s,|]+v?([0-9]+\.[0-9]+[0-9A-Za-z.\-+]*)#', $leading, $m ) ) {
			$name = trim( $m[1] );
			if ( ! $this->is_stopword_name( $name ) ) {
				$c             = new Component( $name );
				$c->version    = $m[2];
				$c->confidence = IDENTIFIED;
				$c->path       = $this->rel( $file );
				$c->evidence   = 'preserved banner in ' . basename( $file );
				return $c;
			}
		}

		// A CDN rewrite header, which names the package authoritatively. It has
		// to be the real header shape inside the LEADING comment, not any
		// mention of a CDN URL anywhere in the first few kilobytes.
		if ( '' !== $leading && preg_match( '#Original file:\s*/npm/((?:@[^/@\s]+/)?[^/@\s]+)@([0-9][0-9A-Za-z.\-+]*)#', $leading, $m ) ) {
			$c             = new Component( $m[1] );
			$c->version    = $m[2];
			$c->confidence = IDENTIFIED;
			$c->purl       = $this->npm_purl( $m[1], $m[2] );
			$c->path       = $this->rel( $file );
			$c->evidence   = 'CDN rewrite header in ' . basename( $file );
			return $c;
		}

		// Machine-generated bundles carry no banner and are often not named
		// .min. at all: the standard block build emits build/index.js.
		if ( $this->looks_minified( $file ) ) {
			if ( null !== $this->find_source_for( $file ) ) {
				return null; // Built from a source in this tree, so the author's own.
			}
			$c             = new Component( basename( $file ) );
			$c->confidence = UNIDENTIFIED;
			$c->path       = $this->rel( $file );
			$c->evidence   = 'machine generated bundle with no banner and no source in this tree';
			return $c;
		}

		return null;
	}

	private function is_stopword_name( string $name ): bool {
		foreach ( $this->tokens( $name ) as $token ) {
			if ( in_array( $token, self::BANNER_STOPWORDS, true ) ) {
				return true;
			}
		}
		return false;
	}

	/** The opening comment block, which is where a banner has to be to count. */
	private function leading_comment( string $head ): string {
		if ( preg_match( '#^\s*(/\*.*?\*/)#s', $head, $m ) ) {
			return $m[1];
		}
		if ( preg_match( '#^\s*((?://[^\n]*\n)+)#', $head, $m ) ) {
			return $m[1];
		}
		return '';
	}

	/**
	 * Decide "minified" from content rather than from the filename.
	 *
	 * Keying on ".min." made the default block build invisible, since it emits
	 * build/index.js with every inlined dependency and no banner.
	 */
	private function looks_minified( string $file ): bool {
		$size = @filesize( $file );
		if ( false === $size || $size < 512 ) {
			return false; // Too small to be a bundle of anything.
		}
		$sample = $this->head( $file, 65536 );
		if ( '' === $sample ) {
			return false;
		}
		$lines = substr_count( $sample, "\n" ) + 1;
		return ( strlen( $sample ) / $lines ) > 200.0;
	}

	/**
	 * Look for a plausible source anywhere in the tree, by stem.
	 *
	 * The old test was a same-directory sibling, which called every src/ to
	 * dist/ layout and every Sass build third party code.
	 */
	private function find_source_for( string $file ): ?string {
		$this->build_stem_index();

		$base = basename( $file );
		$stem = strtolower( (string) preg_replace( '/\.(min|bundle|prod)\./i', '.', $base ) );
		$stem = (string) preg_replace( '/\.(js|css)$/i', '', $stem );
		$stem = $this->stem( $stem );

		if ( '' === $stem || ! isset( $this->stem_index[ $stem ] ) ) {
			return null;
		}
		foreach ( $this->stem_index[ $stem ] as $candidate ) {
			if ( $candidate !== $file ) {
				return $candidate;
			}
		}
		return null;
	}

	private function build_stem_index(): void {
		if ( $this->stem_built ) {
			return;
		}
		$this->stem_built = true;

		foreach ( $this->walk( $this->root ) as $path ) {
			if ( ! preg_match( '/\.(js|jsx|ts|tsx|css|scss|sass|less|styl)$/i', $path ) ) {
				continue;
			}
			if ( false !== strpos( $path, '/node_modules/' ) ) {
				continue;
			}
			$base = strtolower( basename( $path ) );
			$base = (string) preg_replace( '/\.(min|bundle|prod)\./i', '.', $base );
			$base = (string) preg_replace( '/\.[a-z]+$/i', '', $base );
			$key  = $this->stem( $base );
			if ( '' !== $key ) {
				$this->stem_index[ $key ][] = $path;
			}
		}
	}

	/* --------------------------------------------------------------------
	 * Hygiene
	 * ----------------------------------------------------------------- */

	private function detect_shipping_hygiene(): void {
		foreach ( $this->directories( self::MAX_CANDIDATE_DEPTH ) as $dir ) {
			$base = basename( $dir );
			if ( 'node_modules' === $base ) {
				$this->note( $this->rel( $dir ) . ' is present. If it ships, every package in it is part of your product.' );
			}
			if ( '.git' === $base ) {
				$this->note( $this->rel( $dir ) . ' is present. This looks like a working tree rather than a build. Point this tool at what you actually ship for an accurate answer.' );
			}
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

	/** Escape glob metacharacters in a path so a literal path is not read as a pattern. */
	private function esc( string $path ): string {
		return (string) preg_replace( '/([*?\[\]])/', '[$1]', $path );
	}

	private function head( string $path, int $bytes ): string {
		$contents = @file_get_contents( $path, false, null, 0, $bytes );
		return false === $contents ? '' : $contents;
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
			if ( $path === $claimed || 0 === strpos( $path, $claimed . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/** Every directory under the root, breadth first, to a bounded depth. */
	private function directories( int $max_depth ): array {
		$out   = array();
		$queue = array( array( $this->root, 0 ) );

		while ( $queue ) {
			list( $dir, $depth ) = array_shift( $queue );
			if ( $depth >= $max_depth ) {
				continue;
			}
			$children = glob( $this->esc( $dir ) . '/*', GLOB_ONLYDIR );
			if ( false === $children ) {
				continue;
			}
			foreach ( $children as $sub ) {
				$base = basename( $sub );
				if ( in_array( $base, self::SKIP_DIRS, true ) ) {
					// Still worth mentioning a .git, just not worth walking.
					$out[] = $sub;
					continue;
				}
				$out[]   = $sub;
				$queue[] = array( $sub, $depth + 1 );
			}
		}
		return $out;
	}

	/** Shallow PHP files, for cheap inspection of what a directory contains. */
	private function php_files_shallow( string $dir, int $depth ): array {
		$out  = glob( $this->esc( $dir ) . '/*.php' ) ?: array();
		if ( $depth > 1 ) {
			foreach ( glob( $this->esc( $dir ) . '/*', GLOB_ONLYDIR ) ?: array() as $sub ) {
				$out = array_merge( $out, glob( $this->esc( $sub ) . '/*.php' ) ?: array() );
			}
		}
		return $out;
	}

	/**
	 * Does this directory contain PHP?
	 *
	 * Returns 'yes', 'no', or 'unknown' when the budget ran out. Collapsing
	 * 'unknown' into 'no' silently deleted whole packages from the report while
	 * the summary still claimed there were no gaps.
	 */
	private function contains_php( string $dir ): string {
		$budget = 400;
		foreach ( $this->walk( $dir ) as $file ) {
			if ( $budget-- <= 0 ) {
				return 'unknown';
			}
			if ( preg_match( '/\.php$/i', $file ) ) {
				return 'yes';
			}
		}
		return 'no';
	}

	private function find_files( string $filename, int $max_depth ): array {
		$out  = array();
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
			foreach ( glob( $this->esc( $dir ) . '/*', GLOB_ONLYDIR ) ?: array() as $sub ) {
				$base = basename( $sub );
				if ( in_array( $base, self::SKIP_DIRS, true ) || 'node_modules' === $base ) {
					continue;
				}
				$dirs[] = array( $sub, $depth + 1 );
			}
		}
		return $out;
	}

	/**
	 * Yield every file under a directory.
	 *
	 * An unreadable directory is reported as a note rather than thrown, because
	 * a directory the tool could not open is exactly the "code I cannot account
	 * for" this report exists to surface. It should be a line in the output,
	 * not a stack trace that loses the whole run.
	 */
	private function walk( string $dir ): \Generator {
		try {
			$directory = new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS );
		} catch ( \Throwable $e ) {
			$this->note( 'Could not read ' . $this->rel( $dir ) . ', so its contents are not in this report.' );
			return;
		}

		$filtered = new \RecursiveCallbackFilterIterator(
			$directory,
			static function ( $current ) {
				return ! ( $current->isDir() && in_array( $current->getFilename(), self::SKIP_DIRS, true ) );
			}
		);

		$iterator = new \RecursiveIteratorIterator(
			$filtered,
			\RecursiveIteratorIterator::LEAVES_ONLY,
			\RecursiveIteratorIterator::CATCH_GET_CHILD
		);

		foreach ( $iterator as $file ) {
			try {
				if ( $file->isFile() ) {
					++$this->files_seen;
					yield $file->getPathname();
				}
			} catch ( \Throwable $e ) {
				continue;
			}
		}
	}

	private function read_json( string $path ) {
		if ( ! is_file( $path ) ) {
			return null;
		}
		$raw = @file_get_contents( $path );
		if ( false === $raw ) {
			$this->note( 'Could not read ' . $this->rel( $path ) . '.' );
			return null;
		}
		$data = json_decode( $raw, true );
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

	/** SPDX identifiers we emit as license.id rather than license.name. */
	private const SPDX = array(
		'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0',
		'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later',
		'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
		'AGPL-3.0-only', 'AGPL-3.0-or-later', 'Unlicense', 'CC0-1.0',
	);

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
				// The scanner's caveats belong in the document. A consumer
				// reading only the component list would otherwise never learn
				// that part of the tree could not be examined.
				'properties' => self::notes( $result['notes'] ),
			),
			'components'   => $components,
		);

		$json = json_encode( $bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );

		if ( false === $json ) {
			fwrite( STDERR, 'Could not encode the document: ' . json_last_error_msg() . "\n" );
			exit( 1 );
		}

		return $json . "\n";
	}

	private static function notes( array $notes ): array {
		$out = array();
		foreach ( $notes as $i => $note ) {
			$out[] = array( 'name' => 'bodholdt:note:' . ( $i + 1 ), 'value' => $note );
		}
		return $out;
	}

	private static function component( Component $c ): array {
		$out = array(
			'type' => $c->type,
			'name' => $c->name,
		);

		// CycloneDX 1.6 requires only type and name. Writing "unknown" into
		// version asserts a version that does not exist.
		if ( null !== $c->version ) {
			$out['version'] = $c->version;
		}
		if ( $c->purl ) {
			$out['purl'] = $c->purl;
		}
		if ( $c->licenses ) {
			$out['licenses'] = array_values(
				array_map(
					static function ( $l ) {
						return in_array( $l, self::SPDX, true )
							? array( 'license' => array( 'id' => $l ) )
							: array( 'license' => array( 'name' => $l ) );
					},
					$c->licenses
				)
			);
		}

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
		$out .= 'Bodholdt SBOM ' . VERSION . "\n";
		$out .= "Subject: {$subject}\n";
		$out .= 'Scanned at ' . gmdate( 'Y-m-d H:i:s' ) . " UTC\n";
		$out .= str_repeat( '=', 72 ) . "\n";

		$out .= self::section(
			'IDENTIFIED',
			'Name and version both established from a manifest or a preserved banner. These are the ones you can answer questions about.',
			$by_confidence[ IDENTIFIED ]
		);

		$out .= self::section(
			'PARTIALLY IDENTIFIED',
			'Found and named, but something is inferred or missing. A version read out of source code is a good guess, not a declaration, and it is recorded here rather than above.',
			$by_confidence[ PARTIAL ]
		);

		$out .= self::section(
			'NOT IDENTIFIED',
			'Code is present here and this tool could not attribute it. It may be third party, or it may be yours. Either way you cannot report a vulnerability in a component you cannot name, so this is the list that matters.',
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
			$out .= "  Not part of the shipped product. Listed in the CycloneDX output.\n";
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

		$out .= "\nThis tool reports what it can see in a directory. It cannot see code that\n";
		$out .= "was copied in file by file and mixed into your own source. It is not legal\n";
		$out .= "advice and it does not tell you whether any obligation applies to you.\n";

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

	/**
	 * Read a CycloneDX document into name => version.
	 *
	 * Includes metadata.component, which is the product itself, so that a
	 * release to release comparison reports the product's own version change.
	 * Recurses into nested components, which the spec allows.
	 */
	private static function load( string $path ): array {
		if ( ! is_file( $path ) ) {
			fwrite( STDERR, "No such file: {$path}\n" );
			exit( 2 );
		}
		$data = json_decode( (string) file_get_contents( $path ), true );
		if ( ! is_array( $data ) ) {
			fwrite( STDERR, "Could not read {$path} as JSON.\n" );
			exit( 2 );
		}
		if ( ( $data['bomFormat'] ?? null ) !== 'CycloneDX' ) {
			fwrite( STDERR, "Not a CycloneDX document: {$path}\n" );
			exit( 2 );
		}

		$out = array();

		$subject = $data['metadata']['component'] ?? null;
		if ( is_array( $subject ) && isset( $subject['name'] ) ) {
			$out[ (string) $subject['name'] . ' (the product)' ] = (string) ( $subject['version'] ?? 'unknown' );
		}

		$collect = static function ( array $components ) use ( &$collect, &$out ): void {
			foreach ( $components as $c ) {
				if ( ! is_array( $c ) || ! isset( $c['name'] ) ) {
					continue;
				}
				$key = isset( $c['purl'] ) ? (string) $c['purl'] : (string) $c['name'];
				$key = preg_replace( '/@[^@]*$/', '', $key ) ?: (string) $c['name'];
				$out[ $key ] = (string) ( $c['version'] ?? 'unknown' );
				if ( isset( $c['components'] ) && is_array( $c['components'] ) ) {
					$collect( $c['components'] );
				}
			}
		};
		$collect( (array) ( $data['components'] ?? array() ) );

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
		return emit( Diff::render( $diff[0], $diff[1] ), $output );
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
	if ( null !== $output && '' === trim( $output ) ) {
		fwrite( STDERR, "--output needs a filename.\n" );
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
	if ( false === @file_put_contents( $output, $content ) ) {
		fwrite( STDERR, "Could not write to {$output}\n" );
		return 1;
	}
	fwrite( STDERR, "Written to {$output}\n" );
	return 0;
}

exit( main( $argv ) );
