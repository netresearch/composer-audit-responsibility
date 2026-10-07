<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

use Composer\Advisory\Auditor;
use Composer\Advisory\IgnoredSecurityAdvisory;
use Composer\Advisory\PartialSecurityAdvisory;
use Composer\Config;
use Composer\Policy\PolicyConfig;
use Composer\Semver\VersionParser;

/**
 * Applies the root project's own advisory ignore configuration to the
 * post-install audit, with the semantics Composer uses when it blocks.
 *
 * Composer 2.10+ (Composer\Policy\PolicyConfig exists): the ignore lists come
 * from PolicyConfig, scoped to the "block" operation, and the matching is done
 * by Composer's own Auditor::processAdvisories(). That covers
 * policy.advisories.ignore / ignore-id / ignore-severity and, when
 * policy.advisories is absent, the legacy audit.ignore / audit.ignore-severity.
 *
 * Older Composer versions have no single API for the block-scoped ignore list
 * (AuditConfig changed shape several times within 2.9.x, and 2.6-2.8 have no
 * processAdvisories() at all). For those, audit.ignore and audit.ignore-severity
 * are parsed and matched here the way Composer 2.10 treats the legacy keys.
 *
 * It also reports whether the project lets advisories block at all
 * (policy: false, policy.advisories: false, policy.advisories.block: false,
 * or the legacy audit.block-insecure: false), as Composer reads it.
 */
final class RootIgnoreFilter
{
    /**
     * @param array<string, string|null> $ignoreList        Advisory ID, CVE, remote ID or package name => reason
     * @param array<string, string|null> $ignoredSeverities Severity => reason
     */
    private function __construct(
        private readonly array $ignoreList,
        private readonly array $ignoredSeverities,
        private readonly bool $useComposerAuditor,
        private readonly bool $blocking,
    ) {}

    /**
     * Whether the project's configuration lets advisories block at all.
     */
    public function blocksAdvisories(): bool
    {
        return $this->blocking;
    }

    public static function fromConfig(Config $config, ?bool $usePolicyConfig = null): self
    {
        $usePolicyConfig ??= class_exists(PolicyConfig::class);

        if ($usePolicyConfig) {
            $advisories = PolicyConfig::fromConfig($config)->advisories;

            return new self(
                $advisories->getIgnoreListForOperation('block'),
                $advisories->getIgnoreSeverityForOperation('block'),
                true,
                $advisories->block,
            );
        }

        $audit = $config->get('audit');
        $audit = \is_array($audit) ? $audit : [];

        return new self(
            self::parseLegacyBlockIgnores($audit['ignore'] ?? []),
            self::parseLegacyBlockIgnores($audit['ignore-severity'] ?? []),
            false,
            (bool) ($audit['block-insecure'] ?? true),
        );
    }

    /**
     * Split advisories into the ones that block and the ones the project ignores.
     *
     * "blocking" maps advisory ID => package name.
     *
     * @param array<string, list<array<mixed>>> $advisoriesByPackage Package name => raw Packagist advisory entries
     *
     * @return array{blocking: array<string, string>, ignored: list<array{id: string, package: string, reason: string|null}>}
     */
    public function partition(array $advisoriesByPackage): array
    {
        $blocking = [];
        $ignored = [];
        $parser = new VersionParser();
        $objects = [];

        foreach ($advisoriesByPackage as $packageName => $entries) {
            foreach ($entries as $entry) {
                $id = $entry['advisoryId'] ?? $entry['cve'] ?? null;
                if (!\is_string($id) || $id === '') {
                    continue;
                }

                $reason = null;
                if ($this->useComposerAuditor) {
                    if (\is_string($entry['advisoryId'] ?? null) && \is_string($entry['affectedVersions'] ?? null)) {
                        $objects[$packageName][] = PartialSecurityAdvisory::create($packageName, $entry, $parser);
                        continue;
                    }
                } elseif ($this->matches($packageName, $entry, $reason)) {
                    $ignored[] = ['id' => $id, 'package' => $packageName, 'reason' => $reason];
                    continue;
                }

                // Entries Composer could not build an advisory from stay blocking.
                $blocking[$id] = $packageName;
            }
        }

        if ($objects !== []) {
            $result = (new Auditor())->processAdvisories($objects, $this->ignoreList, $this->ignoredSeverities);

            foreach ($result['advisories'] as $packageName => $advisories) {
                foreach ($advisories as $advisory) {
                    $blocking[$advisory->advisoryId] = (string) $packageName;
                }
            }

            foreach ($result['ignoredAdvisories'] as $packageName => $advisories) {
                foreach ($advisories as $advisory) {
                    $ignored[] = [
                        'id' => $advisory->advisoryId,
                        'package' => (string) $packageName,
                        'reason' => $advisory instanceof IgnoredSecurityAdvisory
                            ? $advisory->ignoreReason
                            : $this->ignoreList[$advisory->advisoryId] ?? $this->ignoreList[$packageName] ?? null,
                    ];
                }
            }
        }

        return ['blocking' => $blocking, 'ignored' => $ignored];
    }

    /**
     * Fallback matcher for Composer < 2.10, mirroring Auditor::processAdvisories() of 2.10.
     *
     * @param array<mixed> $entry
     */
    private function matches(string $packageName, array $entry, ?string &$reason): bool
    {
        $severity = $entry['severity'] ?? null;
        if (\is_string($severity) && \array_key_exists($severity, $this->ignoredSeverities)) {
            $reason = $this->ignoredSeverities[$severity] ?? $severity . ' severity is ignored';

            return true;
        }

        $keys = [$packageName, $entry['advisoryId'] ?? null, $entry['cve'] ?? null];
        foreach (\is_array($entry['sources'] ?? null) ? $entry['sources'] : [] as $source) {
            $keys[] = \is_array($source) ? $source['remoteId'] ?? null : null;
        }

        foreach ($keys as $key) {
            if (\is_string($key) && \array_key_exists($key, $this->ignoreList)) {
                $reason = $this->ignoreList[$key];

                return true;
            }
        }

        return false;
    }

    /**
     * Parse audit.ignore / audit.ignore-severity into the entries that apply when blocking.
     *
     * Accepted shapes (as in Composer): ["ID"], {"ID": "reason"}, {"ID": {"apply": "audit|block|all", "reason": "..."}}.
     *
     * @return array<string, string|null>
     */
    private static function parseLegacyBlockIgnores(mixed $config): array
    {
        if (!\is_array($config)) {
            return [];
        }

        $result = [];
        foreach ($config as $key => $value) {
            $id = \is_int($key) ? $value : $key;
            if (!\is_string($id)) {
                continue;
            }

            $reason = null;
            if (\is_string($value) && \is_string($key)) {
                $reason = $value;
            } elseif (\is_array($value)) {
                if (!\in_array($value['apply'] ?? 'all', ['block', 'all'], true)) {
                    continue;
                }
                $reason = \is_string($value['reason'] ?? null) ? $value['reason'] : null;
            }

            $result[$id] = $reason;
        }

        return $result;
    }
}
