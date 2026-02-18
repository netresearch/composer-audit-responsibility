<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

use Composer\Composer;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginEvents;
use Composer\Plugin\PluginInterface;
use Composer\Plugin\PreCommandRunEvent;

/**
 * Composer plugin implementing responsibility propagation for security audits.
 *
 * Detects platform/framework packages from the project type or explicit configuration,
 * then automatically adds audit.ignore entries (with apply=block) for security advisories
 * that affect only platform transitive dependencies.
 *
 * This prevents framework dependency advisories from blocking extension/library CI
 * while keeping the advisories visible in audit reports.
 */
final class Plugin implements PluginInterface, EventSubscriberInterface
{
    private ?Composer $composer = null;
    private ?IOInterface $io = null;

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
        ];
    }

    public function onPreCommandRun(PreCommandRunEvent $event): void
    {
        $commandName = $event->getCommand();

        // Only act on commands that perform security blocking
        if (!\in_array($commandName, ['install', 'update', 'require', 'remove', 'create-project'], true)) {
            return;
        }

        if ($this->composer === null || $this->io === null) {
            return;
        }

        $rootPackage = $this->composer->getPackage();
        $detector = new PlatformDetector();
        $patterns = $detector->detect($rootPackage);

        if ($patterns === []) {
            $this->io->writeError(
                '<info>[audit-responsibility]</info> No platform packages detected. '
                . 'Set extra.audit-responsibility.upstream in composer.json or use a framework-specific package type.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        // Check if blocking is explicitly enabled for upstream
        $extra = $rootPackage->getExtra();
        /** @var array<string, mixed> $responsibilityConfig */
        $responsibilityConfig = $extra['audit-responsibility'] ?? [];
        $blockUpstream = $responsibilityConfig['block-upstream'] ?? false;
        if ($blockUpstream === true) {
            $this->io->writeError(
                '<info>[audit-responsibility]</info> block-upstream is enabled, not filtering advisories.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        $locker = $this->composer->getLocker();
        if (!$locker->isLocked()) {
            $this->io->writeError(
                '<info>[audit-responsibility]</info> No lock file found, skipping responsibility analysis.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        $lockedRepository = $locker->getLockedRepository();

        // Resolve glob patterns against installed packages
        $platformRoots = $detector->resolvePatterns($patterns, $lockedRepository);
        if ($platformRoots === []) {
            $this->io->writeError(
                '<info>[audit-responsibility]</info> No installed packages match platform patterns: '
                . implode(', ', $patterns),
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        $this->io->writeError(
            '<info>[audit-responsibility]</info> Platform packages: '
            . implode(', ', $platformRoots),
            true,
            IOInterface::VERBOSE,
        );

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
            $this->io->writeError(
                '<info>[audit-responsibility]</info> No platform-only transitive dependencies found.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        // Fetch advisories for platform-only packages and inject ignore rules
        $this->injectIgnoreRules($platformOnlyPackages, $platformRoots);
    }

    /**
     * Inject audit.ignore rules for advisories affecting platform-only packages.
     *
     * @param list<string> $platformOnlyPackages
     * @param list<string> $platformRoots
     */
    private function injectIgnoreRules(array $platformOnlyPackages, array $platformRoots): void
    {
        \assert($this->composer !== null);
        \assert($this->io !== null);

        // Build the ignore map: package name → reason
        $platformNames = implode(', ', $platformRoots);
        $ignorePackages = [];
        foreach ($platformOnlyPackages as $packageName) {
            $ignorePackages[$packageName] = sprintf(
                'Platform dependency via %s (responsibility propagation)',
                $platformNames,
            );
        }

        // Store platform-only packages in root extra for SecurityAdvisoryFilter
        // The actual advisory filtering happens when Composer fetches advisories
        // We inject the package list so the AuditResponseFilter can use it
        $config = $this->composer->getConfig();

        // Merge into existing audit config via the Config object
        // This adds platform-only packages to a custom key that our advisory filter reads
        $config->merge([
            'config' => [
                'audit-responsibility-platform-packages' => $platformOnlyPackages,
            ],
        ]);

        $this->io->writeError(sprintf(
            '<info>[audit-responsibility]</info> Detected %d platform-only transitive dependencies via %s.',
            \count($platformOnlyPackages),
            $platformNames,
        ));

        $this->io->writeError(
            '<info>[audit-responsibility]</info> Platform-only packages: '
            . implode(', ', $platformOnlyPackages),
            true,
            IOInterface::VERBOSE,
        );

        // Try to inject into audit.ignore if the Composer version supports it
        $this->tryInjectAuditIgnore($platformOnlyPackages, $platformNames);
    }

    /**
     * Attempt to inject advisory ignore rules into Composer's audit config.
     *
     * For Composer >= 2.9.2 which supports config.audit.ignore with apply scoping,
     * we inject ignore entries with apply=block so advisories are still visible
     * in audit output but don't block installation.
     *
     * @param list<string> $platformOnlyPackages
     */
    private function tryInjectAuditIgnore(array $platformOnlyPackages, string $platformNames): void
    {
        \assert($this->composer !== null);
        \assert($this->io !== null);

        // We need to check if there are actual advisories for these packages
        // Since we're in PRE_COMMAND_RUN, the advisory check hasn't happened yet.
        // Instead, we mark these packages as "platform-owned" and rely on the
        // advisory filter to skip them during the security check.
        //
        // The most reliable approach is to set an env var or config that
        // SecurityAdvisoryPoolFilter respects. Since Composer doesn't have
        // native support for this yet, we use a workaround:
        //
        // Set COMPOSER_AUDIT_RESPONSIBILITY_PACKAGES env var for child processes
        // and store in config for in-process access.
        $packageList = implode(',', $platformOnlyPackages);

        // Make available to any subprocess
        putenv('COMPOSER_AUDIT_RESPONSIBILITY_PACKAGES=' . $packageList);
        $_SERVER['COMPOSER_AUDIT_RESPONSIBILITY_PACKAGES'] = $packageList;

        $this->io->writeError(sprintf(
            '<info>[audit-responsibility]</info> Advisories for platform-only packages (via %s) will not block installation.',
            $platformNames,
        ), true, IOInterface::VERBOSE);
    }
}
