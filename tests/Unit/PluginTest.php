<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Unit;

use Composer\Composer;
use Composer\Config;
use Composer\IO\IOInterface;
use Composer\Package\Link;
use Composer\Package\Locker;
use Composer\Package\PackageInterface;
use Composer\Package\RootPackageInterface;
use Composer\Plugin\PluginEvents;
use Composer\Plugin\PreCommandRunEvent;
use Composer\Repository\LockArrayRepository;
use Composer\Script\Event as ScriptEvent;
use Composer\Script\ScriptEvents;
use Composer\Semver\Constraint\MatchAllConstraint;
use Netresearch\ComposerAuditResponsibility\AdvisoryFetcher;
use Netresearch\ComposerAuditResponsibility\Plugin;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Plugin::class)]
final class PluginTest extends TestCase
{
    private Plugin $plugin;
    private Composer $composer;
    private IOInterface $io;

    protected function setUp(): void
    {
        $this->composer = $this->createMock(Composer::class);
        $this->io = $this->createMock(IOInterface::class);

        $this->plugin = new Plugin();
        $this->plugin->activate($this->composer, $this->io);
    }

    protected function tearDown(): void
    {
        // Clean up env var that onPreCommandRun may set
        unset($_SERVER['COMPOSER_NO_SECURITY_BLOCKING']);
        putenv('COMPOSER_NO_SECURITY_BLOCKING');
    }

    #[Test]
    public function getSubscribedEventsReturnsExpectedListeners(): void
    {
        $events = Plugin::getSubscribedEvents();

        self::assertArrayHasKey(PluginEvents::PRE_COMMAND_RUN, $events);
        self::assertArrayHasKey(ScriptEvents::POST_INSTALL_CMD, $events);
        self::assertArrayHasKey(ScriptEvents::POST_UPDATE_CMD, $events);

        self::assertSame(['onPreCommandRun', 50], $events[PluginEvents::PRE_COMMAND_RUN]);
        self::assertSame(['onPostInstall', 50], $events[ScriptEvents::POST_INSTALL_CMD]);
        self::assertSame(['onPostInstall', 50], $events[ScriptEvents::POST_UPDATE_CMD]);
    }

    #[Test]
    public function activateAndDeactivateManageState(): void
    {
        $plugin = new Plugin();

        // Before activate: onPreCommandRun should return early (no composer/io)
        $event = $this->createPreCommandRunEvent('install');
        $plugin->onPreCommandRun($event);
        self::assertArrayNotHasKey('COMPOSER_NO_SECURITY_BLOCKING', $_SERVER);

        // After activate
        $rootPackage = $this->createTypo3RootPackage();
        $this->composer->method('getPackage')->willReturn($rootPackage);
        $plugin->activate($this->composer, $this->io);

        // After deactivate: should return early again
        $plugin->deactivate($this->composer, $this->io);
        $event2 = $this->createPreCommandRunEvent('install');
        $plugin->onPreCommandRun($event2);
        self::assertArrayNotHasKey('COMPOSER_NO_SECURITY_BLOCKING', $_SERVER);
    }

    #[Test]
    public function onPreCommandRunIgnoresUnrelatedCommands(): void
    {
        $rootPackage = $this->createTypo3RootPackage();
        $this->composer->method('getPackage')->willReturn($rootPackage);

        foreach (['show', 'dump-autoload', 'validate', 'config', 'list'] as $command) {
            $event = $this->createPreCommandRunEvent($command);
            $this->plugin->onPreCommandRun($event);
        }

        self::assertArrayNotHasKey('COMPOSER_NO_SECURITY_BLOCKING', $_SERVER);
    }

    #[Test]
    public function onPreCommandRunIgnoresWhenNotActivated(): void
    {
        $plugin = new Plugin();

        $event = $this->createPreCommandRunEvent('install');
        $plugin->onPreCommandRun($event);

        self::assertArrayNotHasKey('COMPOSER_NO_SECURITY_BLOCKING', $_SERVER);
    }

    #[Test]
    public function onPreCommandRunIgnoresNonPlatformPackage(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('library');
        $rootPackage->method('getExtra')->willReturn([]);
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $event = $this->createPreCommandRunEvent('install');
        $this->plugin->onPreCommandRun($event);

        self::assertArrayNotHasKey('COMPOSER_NO_SECURITY_BLOCKING', $_SERVER);
    }

    #[Test]
    public function onPreCommandRunSetsEnvVarForInstallCommands(): void
    {
        $rootPackage = $this->createTypo3RootPackage();
        $this->composer->method('getPackage')->willReturn($rootPackage);

        foreach (['install', 'update', 'require', 'remove', 'create-project'] as $command) {
            unset($_SERVER['COMPOSER_NO_SECURITY_BLOCKING']);
            putenv('COMPOSER_NO_SECURITY_BLOCKING');

            $event = $this->createPreCommandRunEvent($command);
            $this->plugin->onPreCommandRun($event);

            self::assertSame('1', $_SERVER['COMPOSER_NO_SECURITY_BLOCKING'], "Failed for command: $command");
        }
    }

    #[Test]
    public function onPreCommandRunSkipsWhenBlockUpstreamEnabled(): void
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('typo3-cms-extension');
        $rootPackage->method('getExtra')->willReturn([
            'audit-responsibility' => [
                'block-upstream' => true,
            ],
        ]);
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $event = $this->createPreCommandRunEvent('install');
        $this->plugin->onPreCommandRun($event);

        self::assertArrayNotHasKey('COMPOSER_NO_SECURITY_BLOCKING', $_SERVER);
    }

    #[Test]
    public function onPreCommandRunInjectsIgnoreRulesForAudit(): void
    {
        $rootPackage = $this->createTypo3RootPackage([
            'typo3/cms-core' => true,
        ]);
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $lockedRepo = $this->createLockedRepository([
            'typo3/cms-core' => ['firebase/php-jwt'],
            'firebase/php-jwt' => [],
        ]);

        $locker = $this->createMock(Locker::class);
        $locker->method('isLocked')->willReturn(true);
        $locker->method('getLockedRepository')->willReturn($lockedRepo);
        $this->composer->method('getLocker')->willReturn($locker);

        // The fetcher will return advisory IDs that should be injected
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->method('fetchAdvisoryIds')->willReturn([
            'PKSA-1234' => 'Platform dependency via typo3/cms-core (responsibility propagation)',
        ]);

        $config = $this->createMock(Config::class);
        $config->expects(self::once())->method('merge')->with(self::callback(
            static function (array $data): bool {
                return isset($data['config']['audit']['ignore']['PKSA-1234']);
            },
        ));
        $this->composer->method('getConfig')->willReturn($config);

        $plugin = $this->createTestablePlugin($mockFetcher);

        $event = $this->createPreCommandRunEvent('audit');
        $plugin->onPreCommandRun($event);
    }

    #[Test]
    public function onPreCommandRunSkipsAuditWhenNoLockFile(): void
    {
        $rootPackage = $this->createTypo3RootPackage();
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $locker = $this->createMock(Locker::class);
        $locker->method('isLocked')->willReturn(false);
        $this->composer->method('getLocker')->willReturn($locker);

        $event = $this->createPreCommandRunEvent('audit');
        $this->plugin->onPreCommandRun($event);

        // Should not throw, just returns early
        self::assertTrue(true);
    }

    #[Test]
    public function onPostInstallSkipsWhenNotTriggered(): void
    {
        $event = $this->createMock(ScriptEvent::class);
        $event->expects(self::never())->method('getComposer');

        $this->plugin->onPostInstall($event);
    }

    #[Test]
    public function onPostInstallSkipsWhenNotLocked(): void
    {
        // Trigger blockInsecureDisabled via pre-command
        $rootPackage = $this->createTypo3RootPackage();
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $event = $this->createPreCommandRunEvent('install');
        $this->plugin->onPreCommandRun($event);

        // Now create post-install event with unlocked locker
        $postComposer = $this->createMock(Composer::class);
        $locker = $this->createMock(Locker::class);
        $locker->method('isLocked')->willReturn(false);
        $postComposer->method('getLocker')->willReturn($locker);

        $postEvent = $this->createMock(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($postComposer);
        $postEvent->method('getIO')->willReturn($this->io);

        $this->plugin->onPostInstall($postEvent);

        // Should not throw
        self::assertTrue(true);
    }

    #[Test]
    public function onPostInstallSkipsWhenNoPlatformRoots(): void
    {
        $rootPackage = $this->createTypo3RootPackage();
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $event = $this->createPreCommandRunEvent('install');
        $this->plugin->onPreCommandRun($event);

        // Post-install with repo that has NO typo3/cms-* packages
        $postRootPackage = $this->createTypo3RootPackage();
        $postComposer = $this->createMock(Composer::class);
        $postComposer->method('getPackage')->willReturn($postRootPackage);

        $lockedRepo = $this->createLockedRepository([
            'some/library' => [],
        ]);

        $locker = $this->createMock(Locker::class);
        $locker->method('isLocked')->willReturn(true);
        $locker->method('getLockedRepository')->willReturn($lockedRepo);
        $postComposer->method('getLocker')->willReturn($locker);

        $postEvent = $this->createMock(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($postComposer);
        $postEvent->method('getIO')->willReturn($this->io);

        $this->plugin->onPostInstall($postEvent);

        self::assertTrue(true);
    }

    #[Test]
    public function onPostInstallReportsCleanWhenNoAdvisories(): void
    {
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->method('fetchAdvisoryIds')->willReturn([]);

        $plugin = $this->createTestablePlugin($mockFetcher);

        $rootPackage = $this->createTypo3RootPackage(['typo3/cms-core' => true]);
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $preEvent = $this->createPreCommandRunEvent('install');
        $plugin->onPreCommandRun($preEvent);

        $lockedRepo = $this->createLockedRepository([
            'typo3/cms-core' => ['firebase/php-jwt'],
            'firebase/php-jwt' => [],
            'my/library' => [],
        ]);

        $postComposer = $this->createMock(Composer::class);
        $postRootPackage = $this->createTypo3RootPackage(['typo3/cms-core' => true, 'my/library' => true]);
        $postComposer->method('getPackage')->willReturn($postRootPackage);

        $locker = $this->createMock(Locker::class);
        $locker->method('isLocked')->willReturn(true);
        $locker->method('getLockedRepository')->willReturn($lockedRepo);
        $postComposer->method('getLocker')->willReturn($locker);

        $postEvent = $this->createMock(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($postComposer);
        $postEvent->method('getIO')->willReturn($this->io);

        // Should not throw
        $plugin->onPostInstall($postEvent);
        self::assertTrue(true);
    }

    #[Test]
    public function onPostInstallThrowsOnUserOwnedAdvisories(): void
    {
        $callCount = 0;
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->method('fetchAdvisoryIds')->willReturnCallback(
            function () use (&$callCount): array {
                $callCount++;
                // First call is for user-owned packages, second for platform-only
                if ($callCount === 1) {
                    return ['CVE-2026-9999' => 'User-owned dependency'];
                }

                return [];
            },
        );

        $plugin = $this->createTestablePlugin($mockFetcher);

        $rootPackage = $this->createTypo3RootPackage(['typo3/cms-core' => true, 'my/library' => true]);
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $preEvent = $this->createPreCommandRunEvent('install');
        $plugin->onPreCommandRun($preEvent);

        $lockedRepo = $this->createLockedRepository([
            'typo3/cms-core' => ['firebase/php-jwt'],
            'firebase/php-jwt' => [],
            'my/library' => ['vulnerable/package'],
            'vulnerable/package' => [],
        ]);

        $postComposer = $this->createMock(Composer::class);
        $postRootPackage = $this->createTypo3RootPackage(['typo3/cms-core' => true, 'my/library' => true]);
        $postComposer->method('getPackage')->willReturn($postRootPackage);

        $locker = $this->createMock(Locker::class);
        $locker->method('isLocked')->willReturn(true);
        $locker->method('getLockedRepository')->willReturn($lockedRepo);
        $postComposer->method('getLocker')->willReturn($locker);

        $postEvent = $this->createMock(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($postComposer);
        $postEvent->method('getIO')->willReturn($this->io);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/1 security advisory/');

        $plugin->onPostInstall($postEvent);
    }

    #[Test]
    public function onPostInstallSuppressesPlatformAdvisories(): void
    {
        $callCount = 0;
        $mockFetcher = $this->createMock(AdvisoryFetcher::class);
        $mockFetcher->method('fetchAdvisoryIds')->willReturnCallback(
            function () use (&$callCount): array {
                $callCount++;
                // First call: user-owned (no advisories)
                if ($callCount === 1) {
                    return [];
                }
                // Second call: platform-only (has advisory)
                return ['PKSA-platform' => 'Platform dependency via typo3/cms-core'];
            },
        );

        $plugin = $this->createTestablePlugin($mockFetcher);

        $rootPackage = $this->createTypo3RootPackage(['typo3/cms-core' => true, 'my/library' => true]);
        $this->composer->method('getPackage')->willReturn($rootPackage);

        $preEvent = $this->createPreCommandRunEvent('install');
        $plugin->onPreCommandRun($preEvent);

        $lockedRepo = $this->createLockedRepository([
            'typo3/cms-core' => ['firebase/php-jwt'],
            'firebase/php-jwt' => [],
            'my/library' => [],
        ]);

        $postComposer = $this->createMock(Composer::class);
        $postRootPackage = $this->createTypo3RootPackage(['typo3/cms-core' => true, 'my/library' => true]);
        $postComposer->method('getPackage')->willReturn($postRootPackage);

        $locker = $this->createMock(Locker::class);
        $locker->method('isLocked')->willReturn(true);
        $locker->method('getLockedRepository')->willReturn($lockedRepo);
        $postComposer->method('getLocker')->willReturn($locker);

        $postEvent = $this->createMock(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($postComposer);
        $postEvent->method('getIO')->willReturn($this->io);

        // Should NOT throw — platform advisories are suppressed, user has none
        $plugin->onPostInstall($postEvent);
        self::assertTrue(true);
    }

    // ──────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────

    private function createPreCommandRunEvent(string $command): PreCommandRunEvent
    {
        $event = $this->createMock(PreCommandRunEvent::class);
        $event->method('getCommand')->willReturn($command);

        return $event;
    }

    /**
     * @param array<string, bool> $requires Package names as keys (values ignored)
     */
    private function createTypo3RootPackage(array $requires = []): RootPackageInterface
    {
        $rootPackage = $this->createMock(RootPackageInterface::class);
        $rootPackage->method('getType')->willReturn('typo3-cms-extension');
        $rootPackage->method('getExtra')->willReturn([]);

        $links = [];
        foreach (array_keys($requires) as $target) {
            $links[$target] = new Link('my/extension', $target, new MatchAllConstraint(), Link::TYPE_REQUIRE, '*');
        }
        $rootPackage->method('getRequires')->willReturn($links);

        return $rootPackage;
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
        $plugin = new class ($fetcher) extends Plugin {
            public function __construct(private AdvisoryFetcher $fetcher) {}

            protected function createAdvisoryFetcher(): AdvisoryFetcher
            {
                return $this->fetcher;
            }
        };

        $plugin->activate($this->composer, $this->io);

        return $plugin;
    }
}
