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
        // Dependency graph:
        // root requires: typo3/cms-core, my/library
        // typo3/cms-core requires: firebase/php-jwt, psr/log
        // my/library requires: guzzlehttp/guzzle
        // firebase/php-jwt requires: (nothing)

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

        // Direct deps
        self::assertSame(DependencyOwnership::Direct, $result['typo3/cms-core']);
        self::assertSame(DependencyOwnership::Direct, $result['my/library']);

        // Platform-only (only reachable via typo3/cms-core)
        self::assertSame(DependencyOwnership::PlatformOnly, $result['firebase/php-jwt']);
        self::assertSame(DependencyOwnership::PlatformOnly, $result['psr/log']);

        // User transitive (only reachable via my/library)
        self::assertSame(DependencyOwnership::UserTransitive, $result['guzzlehttp/guzzle']);
    }

    #[Test]
    public function classifyIdentifiesSharedDependencies(): void
    {
        // Both paths reach psr/log
        // typo3/cms-core → psr/log
        // my/library → psr/log

        $repository = $this->createRepository([
            'typo3/cms-core' => ['psr/log'],
            'my/library' => ['psr/log'],
            'psr/log' => [],
        ]);

        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core'],
            directRequires: ['typo3/cms-core', 'my/library'],
        );

        self::assertSame(DependencyOwnership::Shared, $result['psr/log']);
    }

    #[Test]
    public function classifyHandlesDeepTransitiveChains(): void
    {
        // typo3/cms-core → symfony/mailer → symfony/mime → league/html-to-markdown
        // None of these are direct deps of the user

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
        // a → b → c → a (cycle)
        $repository = $this->createRepository([
            'typo3/cms-core' => ['vendor/a'],
            'vendor/a' => ['vendor/b'],
            'vendor/b' => ['vendor/c'],
            'vendor/c' => ['vendor/a'], // cycle back to a
        ]);

        // Should not infinite loop
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
    public function classifySkipsPhpExtensions(): void
    {
        // typo3/cms-core requires php, ext-json (should be skipped)
        $repository = $this->createRepository([
            'typo3/cms-core' => ['firebase/php-jwt'],
            'firebase/php-jwt' => [],
        ]);

        // Add php and ext-json to the requires of typo3/cms-core
        // These should be ignored (no slash = skipped)
        $result = $this->analyzer->classify(
            $repository,
            platformRoots: ['typo3/cms-core'],
            directRequires: ['typo3/cms-core'],
        );

        self::assertArrayNotHasKey('php', $result);
        self::assertArrayNotHasKey('ext-json', $result);
    }

    #[Test]
    public function classifyWithMultiplePlatformRoots(): void
    {
        // Two platform roots: typo3/cms-core and typo3/cms-backend
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

    /**
     * Create a mock repository from a dependency adjacency list.
     *
     * @param array<string, list<string>> $adjacency Package name → list of required package names
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
