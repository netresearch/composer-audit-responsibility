<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

use Composer\Package\RootPackageInterface;

/**
 * Detects platform/framework packages from the project type and explicit configuration.
 *
 * Maps Composer package types to their corresponding framework package patterns.
 * Explicit configuration in extra.audit-responsibility.upstream always takes precedence.
 */
final class PlatformDetector
{
    /**
     * Known Composer type → framework package pattern mappings.
     *
     * @var array<string, list<string>>
     */
    private const TYPE_MAP = [
        'typo3-cms-extension'    => ['typo3/cms-core'],
        'symfony-bundle'         => ['symfony/framework-bundle', 'symfony/http-kernel'],
        'drupal-module'          => ['drupal/core'],
        'drupal-theme'           => ['drupal/core'],
        'drupal-profile'         => ['drupal/core'],
        'drupal-drush'           => ['drupal/core'],
        'wordpress-plugin'       => ['johnpbloch/wordpress-core', 'roots/wordpress'],
        'wordpress-theme'        => ['johnpbloch/wordpress-core', 'roots/wordpress'],
        'wordpress-muplugin'     => ['johnpbloch/wordpress-core', 'roots/wordpress'],
        'magento2-module'        => ['magento/framework'],
        'magento2-theme'         => ['magento/framework'],
        'magento2-language'      => ['magento/framework'],
        'magento2-library'       => ['magento/framework'],
        'shopware-platform-plugin' => ['shopware/core'],
        'contao-bundle'          => ['contao/core-bundle'],
        'laravel-package'        => ['laravel/framework'],
        'cakephp-plugin'         => ['cakephp/cakephp'],
        'yii2-extension'         => ['yiisoft/yii2'],
        'neos-plugin'            => ['neos/neos'],
        'neos-package'           => ['neos/flow'],
        'flow-package'           => ['neos/flow'],
        'oroplatform-bundle'     => ['oro/platform'],
        'silverstripe-vendormodule' => ['silverstripe/framework'],
        'pimcore-bundle'         => ['pimcore/pimcore'],
    ];

    /**
     * Detect platform root packages from the root package type and explicit config.
     *
     * @return list<string> Package names identified as platform/upstream packages
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
