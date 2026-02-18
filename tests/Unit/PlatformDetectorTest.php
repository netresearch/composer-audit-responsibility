<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Unit;

use Composer\Package\PackageInterface;
use Composer\Package\RootPackageInterface;
use Composer\Repository\RepositoryInterface;
use Netresearch\ComposerAuditResponsibility\PlatformDetector;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PlatformDetector::class)]
final class PlatformDetectorTest extends TestCase
{
    private PlatformDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new PlatformDetector();
    }

    #[Test]
    #[DataProvider('typeDetectionProvider')]
    public function detectFromTypeReturnsExpectedPatterns(string $type, array $expected): void
    {
        self::assertSame($expected, $this->detector->detectFromType($type));
    }

    public static function typeDetectionProvider(): iterable
    {
        yield 'TYPO3 extension' => ['typo3-cms-extension', ['typo3/cms-*']];
        yield 'Symfony bundle' => ['symfony-bundle', ['symfony/*']];
        yield 'Drupal module' => ['drupal-module', ['drupal/core', 'drupal/core-*']];
        yield 'Drupal theme' => ['drupal-theme', ['drupal/core', 'drupal/core-*']];
        yield 'WordPress plugin' => ['wordpress-plugin', ['johnpbloch/wordpress-core', 'roots/wordpress', 'wordpress/*']];
        yield 'Magento 2 module' => ['magento2-module', ['magento/framework', 'magento/module-*']];
        yield 'Shopware plugin' => ['shopware-platform-plugin', ['shopware/*']];
        yield 'Contao bundle' => ['contao-bundle', ['contao/*']];
        yield 'CakePHP plugin' => ['cakephp-plugin', ['cakephp/*']];
        yield 'Neos plugin' => ['neos-plugin', ['neos/*']];
        yield 'Flow package' => ['flow-package', ['neos/*']];
        yield 'Oro platform bundle' => ['oroplatform-bundle', ['oro/*']];
        yield 'SilverStripe module' => ['silverstripe-vendormodule', ['silverstripe/*']];
        yield 'Pimcore bundle' => ['pimcore-bundle', ['pimcore/*']];
        yield 'Laravel package' => ['laravel-package', ['laravel/*', 'illuminate/*']];
        yield 'Yii2 extension' => ['yii2-extension', ['yiisoft/*']];
        yield 'Generic library' => ['library', []];
        yield 'Unknown type' => ['some-custom-type', []];
        yield 'Project type' => ['project', []];
    }

    #[Test]
    public function detectUsesExplicitConfigOverType(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('typo3-cms-extension');
        $rootPackage->method('getExtra')->willReturn([
            'audit-responsibility' => [
                'upstream' => ['custom/framework', 'other/platform-*'],
            ],
        ]);

        $result = $this->detector->detect($rootPackage);

        self::assertSame(['custom/framework', 'other/platform-*'], $result);
    }

    #[Test]
    public function detectFallsBackToTypeWhenNoExplicitConfig(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('typo3-cms-extension');
        $rootPackage->method('getExtra')->willReturn([]);

        $result = $this->detector->detect($rootPackage);

        self::assertSame(['typo3/cms-*'], $result);
    }

    #[Test]
    public function detectReturnsEmptyForLibraryTypeWithNoConfig(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('library');
        $rootPackage->method('getExtra')->willReturn([]);

        self::assertSame([], $this->detector->detect($rootPackage));
    }

    #[Test]
    public function detectIgnoresNonStringUpstreamEntries(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('library');
        $rootPackage->method('getExtra')->willReturn([
            'audit-responsibility' => [
                'upstream' => ['valid/package', 123, null, true, 'another/valid'],
            ],
        ]);

        self::assertSame(['valid/package', 'another/valid'], $this->detector->detect($rootPackage));
    }

    #[Test]
    public function detectIgnoresNonArrayUpstreamConfig(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('typo3-cms-extension');
        $rootPackage->method('getExtra')->willReturn([
            'audit-responsibility' => [
                'upstream' => 'not-an-array',
            ],
        ]);

        // Falls back to type detection
        self::assertSame(['typo3/cms-*'], $this->detector->detect($rootPackage));
    }

    #[Test]
    public function resolvePatternsMatchesGlobsAgainstInstalledPackages(): void
    {
        $repository = $this->createRepositoryWithPackages([
            'typo3/cms-core',
            'typo3/cms-backend',
            'typo3/cms-setup',
            'typo3/cms-extbase',
            'web-auth/webauthn-lib',
            'firebase/php-jwt',
            'psr/log',
        ]);

        $result = $this->detector->resolvePatterns(['typo3/cms-*'], $repository);

        sort($result);
        self::assertSame([
            'typo3/cms-backend',
            'typo3/cms-core',
            'typo3/cms-extbase',
            'typo3/cms-setup',
        ], $result);
    }

    #[Test]
    public function resolvePatternsHandlesExactNames(): void
    {
        $repository = $this->createRepositoryWithPackages([
            'typo3/cms-core',
            'psr/log',
        ]);

        $result = $this->detector->resolvePatterns(['typo3/cms-core'], $repository);

        self::assertSame(['typo3/cms-core'], $result);
    }

    #[Test]
    public function resolvePatternsReturnsEmptyWhenNoMatch(): void
    {
        $repository = $this->createRepositoryWithPackages(['psr/log', 'guzzlehttp/guzzle']);

        $result = $this->detector->resolvePatterns(['typo3/cms-*'], $repository);

        self::assertSame([], $result);
    }

    #[Test]
    public function resolvePatternsHandlesMultiplePatterns(): void
    {
        $repository = $this->createRepositoryWithPackages([
            'symfony/framework-bundle',
            'symfony/http-kernel',
            'symfony/console',
            'doctrine/orm',
        ]);

        $result = $this->detector->resolvePatterns(['symfony/*'], $repository);

        sort($result);
        self::assertSame([
            'symfony/console',
            'symfony/framework-bundle',
            'symfony/http-kernel',
        ], $result);
    }

    #[Test]
    public function getTypeMapReturnsAllMappings(): void
    {
        $map = PlatformDetector::getTypeMap();

        self::assertArrayHasKey('typo3-cms-extension', $map);
        self::assertArrayHasKey('symfony-bundle', $map);
        self::assertArrayHasKey('drupal-module', $map);
        self::assertArrayHasKey('wordpress-plugin', $map);
        self::assertArrayHasKey('magento2-module', $map);
        self::assertGreaterThan(10, \count($map));
    }

    /**
     * @param list<string> $packageNames
     */
    private function createRepositoryWithPackages(array $packageNames): RepositoryInterface
    {
        $packages = [];
        foreach ($packageNames as $name) {
            $package = $this->createMock(PackageInterface::class);
            $package->method('getName')->willReturn($name);
            $packages[] = $package;
        }

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn($packages);

        return $repository;
    }
}
