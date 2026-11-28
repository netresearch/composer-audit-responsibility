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
 *
 * Two lists come out of the detection:
 * - platform patterns (TYPE_MAP): the packages whose dependency trees are the framework's
 *   responsibility; they are the start of the platform graph walk and barriers for the user walk.
 * - upstream patterns (UPSTREAM_MAP): the framework packages themselves, released together with
 *   the framework, whose own advisories are the framework's responsibility too. Always a subset
 *   of the platform patterns.
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
     * Known Composer type → patterns of the framework packages that are upstream themselves.
     *
     * Only packages released together with the framework (same release family, same
     * version tags) are listed; where TYPE_MAP uses a vendor-wide glob that also covers
     * independently released packages, only the framework package itself is listed.
     *
     * @var array<string, list<string>>
     */
    private const UPSTREAM_MAP = [
        // Core and the system extensions are released together.
        'typo3-cms-extension'      => ['typo3/cms-*'],
        'symfony-bundle'           => ['symfony/framework-bundle', 'symfony/http-kernel'],
        // drupal/core-* are subtree splits of drupal/core, tagged with every core release.
        'drupal-module'            => ['drupal/core', 'drupal/core-*'],
        'drupal-theme'             => ['drupal/core', 'drupal/core-*'],
        'drupal-profile'           => ['drupal/core', 'drupal/core-*'],
        'drupal-drush'             => ['drupal/core', 'drupal/core-*'],
        'wordpress-plugin'         => ['johnpbloch/wordpress-core', 'roots/wordpress'],
        'wordpress-theme'          => ['johnpbloch/wordpress-core', 'roots/wordpress'],
        'wordpress-muplugin'       => ['johnpbloch/wordpress-core', 'roots/wordpress'],
        'magento2-module'          => ['magento/framework'],
        'magento2-theme'           => ['magento/framework'],
        'magento2-language'        => ['magento/framework'],
        'magento2-library'         => ['magento/framework'],
        // Splits of the Shopware platform repository, tagged together.
        'shopware-platform-plugin' => ['shopware/core', 'shopware/administration', 'shopware/storefront', 'shopware/elasticsearch'],
        'contao-bundle'            => ['contao/core-bundle'],
        // illuminate/* are the component splits of laravel/framework.
        'laravel-package'          => ['laravel/framework', 'illuminate/*'],
        'cakephp-plugin'           => ['cakephp/cakephp'],
        'yii2-extension'           => ['yiisoft/yii2'],
        'neos-plugin'              => ['neos/neos'],
        'neos-package'             => ['neos/neos', 'neos/flow'],
        'flow-package'             => ['neos/flow'],
        'oroplatform-bundle'       => ['oro/platform'],
        'silverstripe-vendormodule' => ['silverstripe/framework'],
        'pimcore-bundle'           => ['pimcore/pimcore'],
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
     * Detect the patterns of framework packages whose own advisories are upstream.
     *
     * Packages listed in extra.audit-responsibility.upstream are upstream themselves;
     * without explicit config, the framework packages known for the root package type.
     *
     * @return list<string> Package name patterns (may contain * globs)
     */
    public function detectUpstream(RootPackageInterface $rootPackage): array
    {
        $explicit = $this->readExplicitConfig($rootPackage);
        if ($explicit !== []) {
            return $explicit;
        }

        return self::UPSTREAM_MAP[$rootPackage->getType()] ?? [];
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

    /**
     * @return array<string, list<string>>
     */
    public static function getUpstreamMap(): array
    {
        return self::UPSTREAM_MAP;
    }
}
