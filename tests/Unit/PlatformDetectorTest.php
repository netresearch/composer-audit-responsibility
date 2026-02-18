<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Unit;

use Composer\Package\RootPackageInterface;
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
    public function detectFromTypeReturnsExpectedPackages(string $type, array $expected): void
    {
        self::assertSame($expected, $this->detector->detectFromType($type));
    }

    public static function typeDetectionProvider(): iterable
    {
        yield 'TYPO3 extension' => ['typo3-cms-extension', ['typo3/cms-core']];
        yield 'Symfony bundle' => ['symfony-bundle', ['symfony/framework-bundle', 'symfony/http-kernel']];
        yield 'Drupal module' => ['drupal-module', ['drupal/core']];
        yield 'Drupal theme' => ['drupal-theme', ['drupal/core']];
        yield 'WordPress plugin' => ['wordpress-plugin', ['johnpbloch/wordpress-core', 'roots/wordpress']];
        yield 'Magento 2 module' => ['magento2-module', ['magento/framework']];
        yield 'Shopware plugin' => ['shopware-platform-plugin', ['shopware/core']];
        yield 'Contao bundle' => ['contao-bundle', ['contao/core-bundle']];
        yield 'CakePHP plugin' => ['cakephp-plugin', ['cakephp/cakephp']];
        yield 'Neos plugin' => ['neos-plugin', ['neos/neos']];
        yield 'Flow package' => ['flow-package', ['neos/flow']];
        yield 'Oro platform bundle' => ['oroplatform-bundle', ['oro/platform']];
        yield 'SilverStripe module' => ['silverstripe-vendormodule', ['silverstripe/framework']];
        yield 'Pimcore bundle' => ['pimcore-bundle', ['pimcore/pimcore']];
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
                'upstream' => ['custom/framework', 'other/platform'],
            ],
        ]);

        $result = $this->detector->detect($rootPackage);

        self::assertSame(['custom/framework', 'other/platform'], $result);
    }

    #[Test]
    public function detectFallsBackToTypeWhenNoExplicitConfig(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('typo3-cms-extension');
        $rootPackage->method('getExtra')->willReturn([]);

        $result = $this->detector->detect($rootPackage);

        self::assertSame(['typo3/cms-core'], $result);
    }

    #[Test]
    public function detectReturnsEmptyForLibraryTypeWithNoConfig(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('library');
        $rootPackage->method('getExtra')->willReturn([]);

        $result = $this->detector->detect($rootPackage);

        self::assertSame([], $result);
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

        $result = $this->detector->detect($rootPackage);

        self::assertSame(['valid/package', 'another/valid'], $result);
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
        $result = $this->detector->detect($rootPackage);

        self::assertSame(['typo3/cms-core'], $result);
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
}
