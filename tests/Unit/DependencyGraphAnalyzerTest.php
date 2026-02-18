<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Unit;

use Composer\Package\Link;
use Composer\Package\PackageInterface;
use Composer\Repository\RepositoryInterface;
use Composer\Semver\Constraint\MatchAllConstraint;
use Netresearch\ComposerAuditResponsibility\DependencyGraphAnalyzer;
use Netresearch\ComposerAuditResponsibility\DependencyOwnership;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(DependencyGraphAnalyzer::class)]
#[CoversClass(DependencyOwnership::class)]
final class DependencyGraphAnalyzerTest extends TestCase
{
    private DependencyGraphAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new DependencyGraphAnalyzer();
    }

    #[Test]
    public function classifyIdentifiesPlatformOnlyDependencies(): void
    {
        // root requires: typo3/cms-core, my/library
        // typo3/cms-core requires: firebase/php-jwt, psr/log
        // my/library requires: guzzlehttp/guzzle

        $repository = $this->createRepository([
            'typo3/cms-core' => ['firebase/php-jwt', 'psr/log'],
            'firebase/php-jwt' => [],
            'psr/log' => [],
            'my/library' => ['guzzlehttp/guzzle'],
            'guzzlehttp/guzzle' => [],
        ]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core'],
            directRequires: ['typo3/cms-core', 'my/library'],
        );

        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-core']);
        self::assertSame(DependencyOwnership::Direct, $result['my/library']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['firebase/php-jwt']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['psr/log']);
        self::assertSame(DependencyOwnership::UserTransitive, $result['guzzlehttp/guzzle']);
    }

    #[Test]
    public function classifyTreatsUserDepsReachingPlatformAsBarrier(): void
    {
        // The key scenario: user requires typo3/cms-backend AND typo3/cms-core
        // Both are platform packages. typo3/cms-backend → typo3/cms-core → firebase/php-jwt
        // User BFS should NOT traverse into platform packages, so firebase/php-jwt
        // should be PlatformOnly, not Shared.

        $repository = $this->createRepository([
            'typo3/cms-core' => ['firebase/php-jwt', 'psr/log'],
            'typo3/cms-backend' => ['typo3/cms-core', 'typo3/cms-extbase'],
            'typo3/cms-extbase' => ['typo3/cms-core'],
            'firebase/php-jwt' => [],
            'psr/log' => [],
            'my/library' => ['guzzlehttp/guzzle'],
            'guzzlehttp/guzzle' => [],
        ]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core', 'typo3/cms-backend', 'typo3/cms-extbase'],
            directRequires: ['typo3/cms-core', 'typo3/cms-backend', 'my/library'],
        );

        // All typo3/* are platform roots → Direct
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-core']);
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-backend']);
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-extbase']);
        self::assertSame(DependencyOwnership::Direct, $result['my/library']);

        // firebase/php-jwt is only reachable via platform → PlatformOnly
        self::assertSame(DependencyOwnership::PlatformOnly, $result['firebase/php-jwt']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['psr/log']);

        // guzzle is only reachable via user → UserTransitive
        self::assertSame(DependencyOwnership::UserTransitive, $result['guzzlehttp/guzzle']);
    }

    #[Test]
    public function classifyIdentifiesSharedWhenUserDepAlsoRequiresPackage(): void
    {
        // User's own dep (not a platform package) also requires psr/log
        // → psr/log is Shared because user has a non-platform path to it

        $repository = $this->createRepository([
            'typo3/cms-core' => ['psr/log'],
            'my/logging-lib' => ['psr/log'],
            'psr/log' => [],
        ]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core'],
            directRequires: ['typo3/cms-core', 'my/logging-lib'],
        );

        self::assertSame(DependencyOwnership::Shared, $result['psr/log']);
    }

    #[Test]
    public function classifyHandlesDeepTransitiveChains(): void
    {
        // typo3/cms-core → symfony/mailer → symfony/mime → league/html-to-markdown

        $repository = $this->createRepository([
            'typo3/cms-core' => ['symfony/mailer'],
            'symfony/mailer' => ['symfony/mime'],
            'symfony/mime' => ['league/html-to-markdown'],
            'league/html-to-markdown' => [],
        ]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core'],
            directRequires: ['typo3/cms-core'],
        );

        self::assertSame(DependencyOwnership::PlatformOnly, $result['symfony/mailer']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['symfony/mime']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['league/html-to-markdown']);
    }

    #[Test]
    public function classifyHandlesCircularDependencies(): void
    {
        $repository = $this->createRepository([
            'typo3/cms-core' => ['vendor/a'],
            'vendor/a' => ['vendor/b'],
            'vendor/b' => ['vendor/c'],
            'vendor/c' => ['vendor/a'], // cycle
        ]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core'],
            directRequires: ['typo3/cms-core'],
        );

        self::assertSame(DependencyOwnership::PlatformOnly, $result['vendor/a']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['vendor/b']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['vendor/c']);
    }

    #[Test]
    public function classifyHandlesEmptyRepository(): void
    {
        $repository = $this->createRepository([]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core'],
            directRequires: ['typo3/cms-core'],
        );

        self::assertSame([], $result);
    }

    #[Test]
    public function classifyHandlesNoPlatformRoots(): void
    {
        $repository = $this->createRepository([
            'my/library' => ['guzzlehttp/guzzle'],
            'guzzlehttp/guzzle' => [],
        ]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: [],
            directRequires: ['my/library'],
        );

        self::assertSame(DependencyOwnership::Direct, $result['my/library']);
        self::assertSame(DependencyOwnership::UserTransitive, $result['guzzlehttp/guzzle']);
    }

    #[Test]
    public function getPlatformOnlyPackagesReturnsCorrectList(): void
    {
        $repository = $this->createRepository([
            'typo3/cms-core' => ['firebase/php-jwt', 'psr/log'],
            'firebase/php-jwt' => [],
            'psr/log' => [],
            'my/library' => ['guzzlehttp/guzzle'],
            'guzzlehttp/guzzle' => [],
        ]);

        $result = $this->analyzer->getPlatformOnlyPackages(
            $repository,
            platformRoots: ['typo3/cms-core'],
            directRequires: ['typo3/cms-core', 'my/library'],
        );

        sort($result);
        self::assertSame(['firebase/php-jwt', 'psr/log'], $result);
    }

    #[Test]
    public function shouldBlockReturnsFalseOnlyForPlatformOnly(): void
    {
        self::assertTrue(DependencyOwnership::Direct->shouldBlock());
        self::assertTrue(DependencyOwnership::Shared->shouldBlock());
        self::assertTrue(DependencyOwnership::UserTransitive->shouldBlock());
        self::assertFalse(DependencyOwnership::PlatformOnly->shouldBlock());
    }

    #[Test]
    public function classifyWithMultiplePlatformRoots(): void
    {
        $repository = $this->createRepository([
            'typo3/cms-core' => ['firebase/php-jwt'],
            'typo3/cms-backend' => ['typo3/cms-core', 'vendor/unique-backend-dep'],
            'firebase/php-jwt' => [],
            'vendor/unique-backend-dep' => [],
            'my/library' => [],
        ]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core', 'typo3/cms-backend'],
            directRequires: ['typo3/cms-core', 'typo3/cms-backend', 'my/library'],
        );

        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-core']);
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-backend']);
        self::assertSame(DependencyOwnership::Direct, $result['my/library']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['firebase/php-jwt']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['vendor/unique-backend-dep']);
    }

    #[Test]
    public function realWorldTypo3Scenario(): void
    {
        // Simulates actual t3x-nr-passkeys-be dependency graph
        $repository = $this->createRepository([
            'typo3/cms-core' => ['firebase/php-jwt', 'psr/log', 'symfony/console', 'doctrine/dbal'],
            'typo3/cms-backend' => ['typo3/cms-core', 'typo3/cms-extbase'],
            'typo3/cms-setup' => ['typo3/cms-core'],
            'typo3/cms-extbase' => ['typo3/cms-core'],
            'firebase/php-jwt' => [],
            'psr/log' => [],
            'symfony/console' => ['psr/log'],
            'doctrine/dbal' => ['psr/log'],
            'web-auth/webauthn-lib' => ['psr/http-factory', 'spomky-labs/cbor-php'],
            'psr/http-factory' => [],
            'spomky-labs/cbor-php' => [],
        ]);

        // All typo3/cms-* are platform roots (resolved from pattern)
        $platformRoots = ['typo3/cms-core', 'typo3/cms-backend', 'typo3/cms-setup', 'typo3/cms-extbase'];
        $directRequires = ['typo3/cms-core', 'typo3/cms-backend', 'typo3/cms-setup', 'web-auth/webauthn-lib'];

        $result = $this->analyzer->classify($repository, $platformRoots, $directRequires);

        // Direct deps
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-core']);
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-backend']);
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-setup']);
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-extbase']);
        self::assertSame(DependencyOwnership::Direct, $result['web-auth/webauthn-lib']);

        // Platform-only transitives (only reachable through typo3/cms-*)
        self::assertSame(DependencyOwnership::PlatformOnly, $result['firebase/php-jwt']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['symfony/console']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['doctrine/dbal']);

        // psr/log is reachable via platform (typo3/cms-core) AND NOT via user
        // (web-auth/webauthn-lib does NOT require psr/log) → PlatformOnly
        self::assertSame(DependencyOwnership::PlatformOnly, $result['psr/log']);

        // User-only transitives (only reachable through web-auth/webauthn-lib)
        self::assertSame(DependencyOwnership::UserTransitive, $result['psr/http-factory']);
        self::assertSame(DependencyOwnership::UserTransitive, $result['spomky-labs/cbor-php']);

        // Platform-only list should include the framework's transitives
        $platformOnly = $this->analyzer->getPlatformOnlyPackages($repository, $platformRoots, $directRequires);
        sort($platformOnly);
        self::assertSame(['doctrine/dbal', 'firebase/php-jwt', 'psr/log', 'symfony/console'], $platformOnly);
    }

    /**
     * @param array<string, list<string>> $adjacency
     */
    private function createRepository(array $adjacency): RepositoryInterface
    {
        $packages = [];
        foreach ($adjacency as $name => $requires) {
            $package = $this->createMock(PackageInterface::class);
            $package->method('getName')->willReturn($name);

            $links = [];
            foreach ($requires as $target) {
                $link = new Link($name, $target, new MatchAllConstraint(), Link::TYPE_REQUIRE, '*');
                $links[$target] = $link;
            }
            $package->method('getRequires')->willReturn($links);

            $packages[] = $package;
        }

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn($packages);
        $repository->method('findPackage')->willReturnCallback(
            static function (string $name) use ($packages): ?PackageInterface {
                foreach ($packages as $package) {
                    if ($package->getName() === $name) {
                        return $package;
                    }
                }

                return null;
            },
        );

        return $repository;
    }
}
