<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

use Composer\Composer;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginEvents;
use Composer\Plugin\PluginInterface;
use Composer\Plugin\PreCommandRunEvent;
use Composer\Script\Event as ScriptEvent;
use Composer\Script\ScriptEvents;

/**
 * Composer plugin implementing responsibility propagation for security audits.
 *
 * On install/update: disables block-insecure so deps resolve, then runs a
 * responsibility-aware audit post-install that fails on user-owned advisories.
 *
 * On audit: injects ignore rules so only user-owned advisories are reported.
 */
final class Plugin implements PluginInterface, EventSubscriberInterface
{
    private const INSTALL_COMMANDS = ['install', 'update', 'require', 'remove', 'create-project'];
    private const TAG = '<info>[audit-responsibility]</info>';

    private ?Composer $composer = null;
    private ?IOInterface $io = null;

    /** @var bool Whether block-insecure was disabled by this plugin (triggers post-install audit) */
    private bool $blockInsecureDisabled = false;

    public function activate(Composer $composer, IOInterface $io): void
    {
        $this->composer = $composer;
        $this->io = $io;
    }

    public function deactivate(Composer $composer, IOInterface $io): void
    {
        $this->composer = null;
        $this->io = null;
    }

    public function uninstall(Composer $composer, IOInterface $io): void
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            PluginEvents::PRE_COMMAND_RUN => ['onPreCommandRun', 50],
            ScriptEvents::POST_INSTALL_CMD => ['onPostInstall', 50],
            ScriptEvents::POST_UPDATE_CMD => ['onPostInstall', 50],
        ];
    }

    public function onPreCommandRun(PreCommandRunEvent $event): void
    {
        $commandName = $event->getCommand();

        $isInstallCommand = \in_array($commandName, self::INSTALL_COMMANDS, true);
        $isAuditCommand = $commandName === 'audit';

        if (!$isInstallCommand && !$isAuditCommand) {
            return;
        }

        if ($this->composer === null || $this->io === null) {
            return;
        }

        $composer = $this->composer;
        $io = $this->io;

        if (!$this->isPlatformPackage($composer, $io)) {
            return;
        }

        // For install/update: disable block-insecure via env var so deps resolve.
        // AuditConfig reads COMPOSER_NO_SECURITY_BLOCKING before the PoolBuilder runs.
        if ($isInstallCommand) {
            $_SERVER['COMPOSER_NO_SECURITY_BLOCKING'] = '1';
            putenv('COMPOSER_NO_SECURITY_BLOCKING=1');

            $this->blockInsecureDisabled = true;

            $io->writeError(
                self::TAG . ' Disabled block-insecure for dependency resolution.',
                true,
                IOInterface::VERBOSE,
            );
        }

        // For audit command: inject ignore rules if lock file exists
        if ($isAuditCommand) {
            $this->injectIgnoreRulesFromLockFile($composer, $io);
        }
    }

    /**
     * After install/update: run responsibility-aware audit.
     *
     * At this point the lock file exists, so we can classify the dependency
     * graph and check for user-owned advisories.
     */
    public function onPostInstall(ScriptEvent $event): void
    {
        if (!$this->blockInsecureDisabled) {
            return;
        }

        $composer = $event->getComposer();
        $io = $event->getIO();

        $locker = $composer->getLocker();
        if (!$locker->isLocked()) {
            return;
        }

        $io->writeError('');
        $io->writeError(self::TAG . ' Running post-install responsibility-aware security audit...');

        $lockedRepository = $locker->getLockedRepository();
        $rootPackage = $composer->getPackage();

        $detector = new PlatformDetector();
        $patterns = $detector->detect($rootPackage);
        $platformRoots = $detector->resolvePatterns($patterns, $lockedRepository);

        if ($platformRoots === []) {
            $io->writeError(self::TAG . ' No platform packages found in lock file.');

            return;
        }

        // Only production requires for blocking classification.
        // Dev dependencies (phpunit, phpstan, etc.) don't ship with the extension;
        // their advisories are reported by `composer audit` but shouldn't block install.
        $directRequires = array_values(array_map(
            static fn ($link) => $link->getTarget(),
            $rootPackage->getRequires(),
        ));

        $analyzer = new DependencyGraphAnalyzer();
        $classifications = $analyzer->classify($lockedRepository, $platformRoots, $directRequires);

        $platformNames = implode(', ', $platformRoots);

        $platformOnlyPackages = [];
        $userOwnedPackages = [];
        foreach ($classifications as $name => $ownership) {
            if ($ownership === DependencyOwnership::PlatformOnly) {
                $platformOnlyPackages[] = $name;
            } else {
                $userOwnedPackages[] = $name;
            }
        }

        $io->writeError(sprintf(
            self::TAG . ' Classified %d packages: %d platform-only, %d user-owned.',
            \count($classifications),
            \count($platformOnlyPackages),
            \count($userOwnedPackages),
        ), true, IOInterface::VERBOSE);

        // Check for advisories on user-owned packages (these SHOULD block).
        // Filter by installed version — only advisories affecting the actual
        // installed version should block, not historical advisories for other versions.
        $fetcher = new AdvisoryFetcher();
        $userAdvisories = $fetcher->fetchAdvisoryIds(
            $userOwnedPackages,
            $lockedRepository,
            'User-owned dependency',
            filterByInstalledVersion: true,
        );

        // Check for advisories on platform-only packages (informational).
        // Also filter by installed version for accurate reporting.
        $platformAdvisories = $fetcher->fetchAdvisoryIds(
            $platformOnlyPackages,
            $lockedRepository,
            'Platform dependency via ' . $platformNames,
            filterByInstalledVersion: true,
        );

        // Report platform-only advisories (suppressed)
        if ($platformAdvisories !== []) {
            $io->writeError(sprintf(
                self::TAG . ' Suppressed %d advisory/ies for platform-only dependencies (framework responsibility):',
                \count($platformAdvisories),
            ));
            foreach ($platformAdvisories as $advisoryId => $reason) {
                $io->writeError(sprintf('  - %s (%s)', $advisoryId, $reason));
            }
        }

        // Report and fail on user-owned advisories
        if ($userAdvisories !== []) {
            $io->writeError('');
            $io->writeError(sprintf(
                '<error>' . self::TAG . ' Found %d security advisory/ies in YOUR dependencies:</error>',
                \count($userAdvisories),
            ));
            foreach ($userAdvisories as $advisoryId => $reason) {
                $io->writeError(sprintf('  <error>- %s</error>', $advisoryId));
            }
            $io->writeError('');
            $io->writeError('<error>These are in packages you control. Update them to resolve.</error>');

            throw new \RuntimeException(sprintf(
                '[audit-responsibility] %d security advisory/ies found in user-owned dependencies. '
                . 'Run "composer audit" for details.',
                \count($userAdvisories),
            ));
        }

        if ($platformAdvisories === []) {
            $io->writeError(self::TAG . ' No security advisories found.');
        } else {
            $io->writeError('');
            $io->writeError(self::TAG . ' No security advisories in YOUR dependencies. All clear.');
        }
    }

    /**
     * Check if the root package is a platform/framework package type and not blocked by config.
     */
    private function isPlatformPackage(Composer $composer, IOInterface $io): bool
    {
        $rootPackage = $composer->getPackage();
        $detector = new PlatformDetector();
        $patterns = $detector->detect($rootPackage);

        if ($patterns === []) {
            $io->writeError(
                self::TAG . ' No platform packages detected. '
                . 'Set extra.audit-responsibility.upstream in composer.json or use a framework-specific package type.',
                true,
                IOInterface::VERBOSE,
            );

            return false;
        }

        $extra = $rootPackage->getExtra();
        /** @var array<string, mixed> $responsibilityConfig */
        $responsibilityConfig = $extra['audit-responsibility'] ?? [];
        $blockUpstream = $responsibilityConfig['block-upstream'] ?? false;
        if ($blockUpstream === true) {
            $io->writeError(
                self::TAG . ' block-upstream is enabled, not filtering advisories.',
                true,
                IOInterface::VERBOSE,
            );

            return false;
        }

        return true;
    }

    /**
     * For the audit command: inject ignore rules from the lock file.
     */
    private function injectIgnoreRulesFromLockFile(Composer $composer, IOInterface $io): void
    {
        $locker = $composer->getLocker();
        if (!$locker->isLocked()) {
            $io->writeError(
                self::TAG . ' No lock file found, skipping responsibility analysis.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        $lockedRepository = $locker->getLockedRepository();
        $rootPackage = $composer->getPackage();

        $detector = new PlatformDetector();
        $patterns = $detector->detect($rootPackage);
        $platformRoots = $detector->resolvePatterns($patterns, $lockedRepository);

        if ($platformRoots === []) {
            $io->writeError(
                self::TAG . ' No installed packages match platform patterns.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        $io->writeError(
            self::TAG . ' Platform packages: ' . implode(', ', $platformRoots),
            true,
            IOInterface::VERBOSE,
        );

        // Only production requires — dev dependency advisories are not suppressed
        // and will still appear in `composer audit` output normally.
        $directRequires = array_values(array_map(
            static fn ($link) => $link->getTarget(),
            $rootPackage->getRequires(),
        ));

        $analyzer = new DependencyGraphAnalyzer();
        $platformOnlyPackages = $analyzer->getPlatformOnlyPackages(
            $lockedRepository,
            $platformRoots,
            $directRequires,
        );

        if ($platformOnlyPackages === []) {
            $io->writeError(
                self::TAG . ' No platform-only transitive dependencies found.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        $platformNames = implode(', ', $platformRoots);
        $io->writeError(sprintf(
            self::TAG . ' Detected %d platform-only transitive dependencies via %s.',
            \count($platformOnlyPackages),
            $platformNames,
        ));

        $reason = sprintf('Platform dependency via %s (responsibility propagation)', $platformNames);
        $fetcher = new AdvisoryFetcher();
        $advisoryIgnores = $fetcher->fetchAdvisoryIds($platformOnlyPackages, $lockedRepository, $reason);

        if ($advisoryIgnores === []) {
            $io->writeError(
                self::TAG . ' No active advisories for platform-only packages.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        $config = $composer->getConfig();
        $config->merge([
            'config' => [
                'audit' => [
                    'ignore' => $advisoryIgnores,
                ],
            ],
        ]);

        $advisoryIds = array_keys($advisoryIgnores);
        $io->writeError(sprintf(
            self::TAG . ' Injected %d advisory ignore rules: %s',
            \count($advisoryIds),
            implode(', ', $advisoryIds),
        ));
    }
}
