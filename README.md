# Composer Audit Responsibility

[![CI](https://github.com/netresearch/composer-audit-responsibility/actions/workflows/ci.yml/badge.svg)](https://github.com/netresearch/composer-audit-responsibility/actions/workflows/ci.yml)
[![Latest Stable Version](https://poser.pugx.org/netresearch/composer-audit-responsibility/v)](https://packagist.org/packages/netresearch/composer-audit-responsibility)
[![License](https://poser.pugx.org/netresearch/composer-audit-responsibility/license)](https://packagist.org/packages/netresearch/composer-audit-responsibility)

A Composer plugin implementing **responsibility propagation** for security audits.

Stops upstream/framework transitive dependency advisories from blocking your library, extension, or plugin CI — while keeping them visible in audit reports.

## The Problem

Since Composer 2.9, `composer install` blocks when any transitive dependency has a security advisory (`block-insecure` defaults to `true`). For library/extension developers, this means:

- Your **TYPO3 extension** requires `typo3/cms-core` for compatibility
- `typo3/cms-core` transitively depends on `firebase/php-jwt`
- When `firebase/php-jwt` gets a security advisory, **your CI breaks**
- You have **no control** over this — you didn't choose `firebase/php-jwt`
- The **TYPO3 team** is responsible for updating their framework dependencies

This affects every framework ecosystem: Drupal modules, Symfony bundles, Laravel packages, WordPress plugins, Magento modules, Shopware plugins, and more.

## The Solution: Responsibility Propagation

Security responsibility follows the dependency chain:

| Role | Responsible For |
|------|----------------|
| **Extension/Plugin developer** | Their direct dependencies |
| **Framework team** | Framework's transitive dependencies |
| **Application/Project assembler** | Everything (they ship the final product) |

This plugin automatically detects your framework dependencies and prevents their transitive security advisories from blocking your `composer install/update`. Advisories are still **reported** — they just don't **block**.

## Installation

```bash
composer require --dev netresearch/composer-audit-responsibility
```

## Configuration

### Automatic Detection

The plugin auto-detects your framework from the `type` field in `composer.json`:

| Package Type | Detected Framework |
|---|---|
| `typo3-cms-extension` | `typo3/cms-core` |
| `symfony-bundle` | `symfony/framework-bundle`, `symfony/http-kernel` |
| `drupal-module` | `drupal/core` |
| `wordpress-plugin` | `johnpbloch/wordpress-core`, `roots/wordpress` |
| `magento2-module` | `magento/framework` |
| `shopware-platform-plugin` | `shopware/core` |
| `contao-bundle` | `contao/core-bundle` |
| `cakephp-plugin` | `cakephp/cakephp` |
| `neos-plugin` | `neos/neos` |
| `flow-package` | `neos/flow` |
| `oroplatform-bundle` | `oro/platform` |
| `silverstripe-vendormodule` | `silverstripe/framework` |
| `pimcore-bundle` | `pimcore/pimcore` |
| `laravel-package` | `laravel/framework` |
| `yii2-extension` | `yiisoft/yii2` |

### Explicit Configuration

For projects that use `type: library` or need custom upstream declarations:

```json
{
    "extra": {
        "audit-responsibility": {
            "upstream": ["typo3/cms-core", "helhum/typo3-console"]
        }
    }
}
```

### Re-enable Blocking for Upstream

If you want framework advisories to block (e.g., in a final application project):

```json
{
    "extra": {
        "audit-responsibility": {
            "block-upstream": true
        }
    }
}
```

## How It Works

1. **Detection** — Identifies platform/framework packages from your `type` or explicit config
2. **Graph analysis** — Walks the dependency graph (BFS) to classify every package:
   - **Direct**: In your `require` — your responsibility
   - **Platform-only**: Only reachable through framework packages — framework's responsibility
   - **Shared**: Reachable through both your deps AND framework — your responsibility (conservative)
   - **User-transitive**: Only reachable through your non-framework deps — your responsibility
3. **Policy enforcement** — Platform-only advisories don't block; everything else still blocks normally

### The Diamond Problem

When a package is reachable through both your dependencies AND the framework:

```
your-extension
├── typo3/cms-core → psr/log (platform path)
└── my/logging-lib → psr/log (user path)
```

**Conservative rule**: If you have ANY dependency path to a package, it's your responsibility. `psr/log` blocks in this case because you chose `my/logging-lib` which also depends on it.

## Comparison with Alternatives

| Approach | Scope | Maintenance | Visibility |
|---|---|---|---|
| `config.audit.ignore` per advisory | Per-advisory | Update for every new advisory | Hidden |
| `COMPOSER_NO_SECURITY_BLOCKING=1` | All deps | None | Hidden |
| **This plugin** | Framework deps only | None (auto-detected) | Preserved |

## Requirements

- PHP >= 8.1
- Composer >= 2.9

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/netresearch/composer-audit-responsibility).
