<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Integration;

use Composer\Composer;
use Composer\Config;
use Composer\IO\IOInterface;
use Composer\Package\Link;
use Composer\Package\Locker;
use Composer\Package\PackageInterface;
use Composer\Package\RootPackageInterface;
use Composer\Plugin\PreCommandRunEvent;
use Composer\Repository\LockArrayRepository;
use Composer\Script\Event as ScriptEvent;
use Composer\Semver\Constraint\MatchAllConstraint;
use Netresearch\ComposerAuditResponsibility\AdvisoryFetcher;
use Netresearch\ComposerAuditResponsibility\Plugin;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Plugin::class)]
final class PluginIntegrationTest extends TestCase
{
    protected function tearDown(): void
    {
        unset($_SERVER['COMPOSER_NO_SECURITY_BLOCKING']);
        putenv('COMPOSER_NO_SECURITY_BLOCKING');
    }

    #[Test]
    public function fullInstallFlowWithTypo3Extension(): void
    {
        // No advisories for any package → clean result
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->method('fetchAdvisoryIds')->willReturn([]);

        $io = $this->createMock(IOInterface::class);
        $composer = $this->createComposer(
            type: 'typo3-cms-extension',
            requires: ['typo3/cms-core', 'my/library'],
            lockedAdjacency: [
                'typo3/cms-core' => ['firebase/php-jwt', 'psr/log'],
                'firebase/php-jwt' => [],
                'psr/log' => [],
                'my/library' => [],
            ],
        );

        $plugin = $this->createTestablePlugin($mockFetcher);
        $plugin->activate($composer, $io);

        // Step 1: pre-command (install)
        $preEvent = $this->createMock(PreCommandRunEvent::class);
        $preEvent->method('getCommand')->willReturn('install');
        $plugin->onPreCommandRun($preEvent);

        self::assertSame('1', $_SERVER['COMPOSER_NO_SECURITY_BLOCKING']);

        // Step 2: post-install
        $postEvent = $this->createMock(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($composer);
        $postEvent->method('getIO')->willReturn($io);

        // Should not throw
        $plugin->onPostInstall($postEvent);
        self::assertTrue(true);
    }

    #[Test]
    public function fullInstallFlowThrowsOnUserAdvisories(): void
    {
        $callCount = 0;
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->method('fetchAdvisoryIds')->willReturnCallback(
            function () use (&$callCount): array {
                $callCount++;
                // First call: user-owned packages → has advisory
                if ($callCount === 1) {
                    return ['CVE-2026-0001' => 'User-owned dependency'];
                }
                // Second call: platform-only → clean
                return [];
            },
        );

        $io = $this->createMock(IOInterface::class);
        $composer = $this->createComposer(
            type: 'typo3-cms-extension',
            requires: ['typo3/cms-core', 'my/library'],
            lockedAdjacency: [
                'typo3/cms-core' => ['firebase/php-jwt'],
                'firebase/php-jwt' => [],
                'my/library' => ['vulnerable/dep'],
                'vulnerable/dep' => [],
            ],
        );

        $plugin = $this->createTestablePlugin($mockFetcher);
        $plugin->activate($composer, $io);

        // Pre-command
        $preEvent = $this->createMock(PreCommandRunEvent::class);
        $preEvent->method('getCommand')->willReturn('install');
        $plugin->onPreCommandRun($preEvent);

        // Post-install should throw on user advisories
        $postEvent = $this->createMock(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($composer);
        $postEvent->method('getIO')->willReturn($io);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/1 security advisory/');
        $plugin->onPostInstall($postEvent);
    }

    #[Test]
    public function fullInstallFlowSuppressesPlatformAdvisories(): void
    {
        $callCount = 0;
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->method('fetchAdvisoryIds')->willReturnCallback(
            function () use (&$callCount): array {
                $callCount++;
                // First call: user-owned → clean
                if ($callCount === 1) {
                    return [];
                }
                // Second call: platform-only → has advisory (suppressed)
                return ['PKSA-fw-123' => 'Platform dependency via typo3/cms-core'];
            },
        );

        $io = $this->createMock(IOInterface::class);
        $composer = $this->createComposer(
            type: 'typo3-cms-extension',
            requires: ['typo3/cms-core', 'my/library'],
            lockedAdjacency: [
                'typo3/cms-core' => ['firebase/php-jwt'],
                'firebase/php-jwt' => [],
                'my/library' => [],
            ],
        );

        $plugin = $this->createTestablePlugin($mockFetcher);
        $plugin->activate($composer, $io);

        $preEvent = $this->createMock(PreCommandRunEvent::class);
        $preEvent->method('getCommand')->willReturn('install');
        $plugin->onPreCommandRun($preEvent);

        $postEvent = $this->createMock(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($composer);
        $postEvent->method('getIO')->willReturn($io);

        // Should NOT throw — platform advisories suppressed, user clear
        $plugin->onPostInstall($postEvent);
        self::assertTrue(true);
    }

    #[Test]
    public function auditCommandInjectsIgnoreRules(): void
    {
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->method('fetchAdvisoryIds')->willReturn([
            'PKSA-upstream-1' => 'Platform dependency via typo3/cms-core (responsibility propagation)',
        ]);

        $config = $this->createMock(Config::class);
        $config->expects(self::once())->method('merge')->with(self::callback(
            static function (array $data): bool {
                return isset($data['config']['audit']['ignore']['PKSA-upstream-1']);
            },
        ));

        $io = $this->createMock(IOInterface::class);
        $composer = $this->createComposer(
            type: 'typo3-cms-extension',
            requires: ['typo3/cms-core', 'my/library'],
            lockedAdjacency: [
                'typo3/cms-core' => ['firebase/php-jwt'],
                'firebase/php-jwt' => [],
                'my/library' => [],
            ],
            config: $config,
        );

        $plugin = $this->createTestablePlugin($mockFetcher);
        $plugin->activate($composer, $io);

        $event = $this->createMock(PreCommandRunEvent::class);
        $event->method('getCommand')->willReturn('audit');
        $plugin->onPreCommandRun($event);
    }

    #[Test]
    public function pluginInactiveForProjectType(): void
    {
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->expects(self::never())->method('fetchAdvisoryIds');

        $io = $this->createMock(IOInterface::class);
        $composer = $this->createComposer(
            type: 'project',
            requires: ['typo3/cms-core'],
            lockedAdjacency: [
                'typo3/cms-core' => [],
            ],
        );

        $plugin = $this->createTestablePlugin($mockFetcher);
        $plugin->activate($composer, $io);

        $event = $this->createMock(PreCommandRunEvent::class);
        $event->method('getCommand')->willReturn('install');
        $plugin->onPreCommandRun($event);

        // project type → plugin does nothing
        self::assertArrayNotHasKey('COMPOSER_NO_SECURITY_BLOCKING', $_SERVER);
    }

    #[Test]
    public function pluginInactiveForLibraryWithoutConfig(): void
    {
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->expects(self::never())->method('fetchAdvisoryIds');

        $io = $this->createMock(IOInterface::class);
        $composer = $this->createComposer(
            type: 'library',
            requires: ['psr/log'],
            lockedAdjacency: [
                'psr/log' => [],
            ],
        );

        $plugin = $this->createTestablePlugin($mockFetcher);
        $plugin->activate($composer, $io);

        $event = $this->createMock(PreCommandRunEvent::class);
        $event->method('getCommand')->willReturn('install');
        $plugin->onPreCommandRun($event);

        // library without explicit config → plugin does nothing
        self::assertArrayNotHasKey('COMPOSER_NO_SECURITY_BLOCKING', $_SERVER);
    }

    // ──────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────

    /**
     * @param list<string>                $requires
     * @param array<string, list<string>> $lockedAdjacency
     */
    private function createComposer(
        string $type,
        array $requires,
        array $lockedAdjacency,
        ?Config $config = null,
    ): Composer {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn($type);
        $rootPackage->method('getExtra')->willReturn([]);

        $links = [];
        foreach ($requires as $target) {
            $links[$target] = new Link('my/extension', $target, new MatchAllConstraint(), Link::TYPE_REQUIRE, '*');
        }
        $rootPackage->method('getRequires')->willReturn($links);

        $lockedRepo = $this->createLockedRepository($lockedAdjacency);

        $locker = $this->createMock(Locker::class);
        $locker->method('isLocked')->willReturn(true);
        $locker->method('getLockedRepository')->willReturn($lockedRepo);

        $composer = $this->createMock(Composer::class);
        $composer->method('getPackage')->willReturn($rootPackage);
        $composer->method('getLocker')->willReturn($locker);

        if ($config !== null) {
            $composer->method('getConfig')->willReturn($config);
        }

        return $composer;
    }

    /**
     * @param array<string, list<string>> $adjacency
     */
    private function createLockedRepository(array $adjacency): LockArrayRepository
    {
        $packages = [];
        foreach ($adjacency as $name => $requires) {
            $package = $this->createMock(PackageInterface::class);
            $package->method('getName')->willReturn($name);
            $package->method('getVersion')->willReturn('1.0.0');

            $links = [];
            foreach ($requires as $target) {
                $links[$target] = new Link($name, $target, new MatchAllConstraint(), Link::TYPE_REQUIRE, '*');
            }
            $package->method('getRequires')->willReturn($links);

            $packages[] = $package;
        }

        $repository = $this->createMock(LockArrayRepository::class);
        $repository->method('getPackages')->willReturn($packages);

        return $repository;
    }

    private function createTestablePlugin(AdvisoryFetcher $fetcher): Plugin
    {
        return new class ($fetcher) extends Plugin {
            public function __construct(private AdvisoryFetcher $fetcher) {}

            protected function createAdvisoryFetcher(): AdvisoryFetcher
            {
                return $this->fetcher;
            }
        };
    }
}
