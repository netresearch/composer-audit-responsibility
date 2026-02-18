<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

use Composer\Package\RootPackageInterface;
use Composer\Repository\RepositoryInterface;

/**
 * Detects platform/framework packages from the project type and explicit configuration.
 *
 * Maps Composer package types to their corresponding framework package patterns.
 * Patterns use fnmatch-style globs (e.g., "typo3/cms-*" matches "typo3/cms-core").
 * Explicit configuration in extra.audit-responsibility.upstream always takes precedence.
 */
final class PlatformDetector
{
    /**
     * Known Composer type → framework package pattern mappings.
     *
     * Values are fnmatch patterns that match against installed package names.
     *
     * @var array<string, list<string>>
     */
    private const TYPE_MAP = [
        'typo3-cms-extension'      => ['typo3/cms-*'],
        'symfony-bundle'           => ['symfony/*'],
        'drupal-module'            => ['drupal/core', 'drupal/core-*'],
        'drupal-theme'             => ['drupal/core', 'drupal/core-*'],
        'drupal-profile'           => ['drupal/core', 'drupal/core-*'],
        'drupal-drush'             => ['drupal/core', 'drupal/core-*'],
        'wordpress-plugin'         => ['johnpbloch/wordpress-core', 'roots/wordpress', 'wordpress/*'],
        'wordpress-theme'          => ['johnpbloch/wordpress-core', 'roots/wordpress', 'wordpress/*'],
        'wordpress-muplugin'       => ['johnpbloch/wordpress-core', 'roots/wordpress', 'wordpress/*'],
        'magento2-module'          => ['magento/framework', 'magento/module-*'],
        'magento2-theme'           => ['magento/framework', 'magento/module-*'],
        'magento2-language'        => ['magento/framework'],
        'magento2-library'         => ['magento/framework'],
        'shopware-platform-plugin' => ['shopware/*'],
        'contao-bundle'            => ['contao/*'],
        'laravel-package'          => ['laravel/*', 'illuminate/*'],
        'cakephp-plugin'           => ['cakephp/*'],
        'yii2-extension'           => ['yiisoft/*'],
        'neos-plugin'              => ['neos/*'],
        'neos-package'             => ['neos/*'],
        'flow-package'             => ['neos/*'],
        'oroplatform-bundle'       => ['oro/*'],
        'silverstripe-vendormodule' => ['silverstripe/*'],
        'pimcore-bundle'           => ['pimcore/*'],
    ];

    /**
     * Detect platform package patterns from the root package type and explicit config.
     *
     * @return list<string> Package name patterns (may contain * globs)
     */
    public function detect(RootPackageInterface $rootPackage): array
    {
        $explicit = $this->readExplicitConfig($rootPackage);
        if ($explicit !== []) {
            return $explicit;
        }

        return $this->detectFromType($rootPackage->getType());
    }

    /**
     * Resolve patterns against installed packages to get actual package names.
     *
     * @param list<string>        $patterns   Patterns from detect() (may contain * globs)
     * @param RepositoryInterface $repository Installed/locked package repository
     *
     * @return list<string> Resolved package names
     */
    public function resolvePatterns(array $patterns, RepositoryInterface $repository): array
    {
        $resolved = [];

        foreach ($repository->getPackages() as $package) {
            $name = $package->getName();
            foreach ($patterns as $pattern) {
                if (fnmatch($pattern, $name)) {
                    $resolved[] = $name;
                    break;
                }
            }
        }

        return $resolved;
    }

    /**
     * @return list<string>
     */
    public function detectFromType(string $type): array
    {
        return self::TYPE_MAP[$type] ?? [];
    }

    /**
     * @return list<string>
     */
    private function readExplicitConfig(RootPackageInterface $rootPackage): array
    {
        $extra = $rootPackage->getExtra();

        if (!\is_array($extra['audit-responsibility'] ?? null)) {
            return [];
        }

        /** @var array<string, mixed> $config */
        $config = $extra['audit-responsibility'];
        $upstream = $config['upstream'] ?? null;

        if (!\is_array($upstream)) {
            return [];
        }

        return array_values(array_filter($upstream, 'is_string'));
    }

    /**
     * @return array<string, list<string>>
     */
    public static function getTypeMap(): array
    {
        return self::TYPE_MAP;
    }
}
