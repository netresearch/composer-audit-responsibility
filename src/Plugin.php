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
 * fetches security advisories for platform-only transitive dependencies, and injects
 * their advisory IDs into Composer's config.audit.ignore with apply=block scope.
 *
 * This prevents framework dependency advisories from blocking extension/library CI
 * while keeping the advisories visible in `composer audit` reports.
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

        // Include both require and require-dev for complete ownership classification
        $directRequires = array_values(array_map(
            static fn ($link) => $link->getTarget(),
            array_merge($rootPackage->getRequires(), $rootPackage->getDevRequires()),
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

        $platformNames = implode(', ', $platformRoots);
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

        // Fetch advisories and inject ignore rules with real advisory IDs
        $this->injectIgnoreRules($platformOnlyPackages, $platformNames, $lockedRepository);
    }

    /**
     * Fetch advisories for platform-only packages and inject their IDs into audit.ignore.
     *
     * @param list<string> $platformOnlyPackages
     */
    private function injectIgnoreRules(
        array $platformOnlyPackages,
        string $platformNames,
        \Composer\Repository\RepositoryInterface $lockedRepository,
    ): void {
        \assert($this->composer !== null);
        \assert($this->io !== null);

        $reason = sprintf('Platform dependency via %s (responsibility propagation)', $platformNames);
        $fetcher = new AdvisoryFetcher();
        $advisoryIgnores = $fetcher->fetchAdvisoryIds($platformOnlyPackages, $lockedRepository, $reason);

        if ($advisoryIgnores === []) {
            $this->io->writeError(
                '<info>[audit-responsibility]</info> No active advisories for platform-only packages.',
                true,
                IOInterface::VERBOSE,
            );

            return;
        }

        // Inject advisory IDs into Composer's config.audit.ignore
        // Format: { "ADVISORY-ID": "reason" } or { "ADVISORY-ID": { "reason": "...", "apply": "block" } }
        $config = $this->composer->getConfig();
        $config->merge([
            'config' => [
                'audit' => [
                    'ignore' => $advisoryIgnores,
                ],
            ],
        ]);

        $advisoryIds = array_keys($advisoryIgnores);
        $this->io->writeError(sprintf(
            '<info>[audit-responsibility]</info> Injected %d advisory ignore rules (apply=block): %s',
            \count($advisoryIds),
            implode(', ', $advisoryIds),
        ));
    }
}
