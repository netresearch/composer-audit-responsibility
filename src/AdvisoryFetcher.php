<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

use Composer\Repository\RepositoryInterface;
use Composer\Semver\Semver;

/**
 * Fetches security advisories from Packagist for specific packages.
 *
 * Uses the Packagist Security Advisories API to get current advisories,
 * then extracts advisory IDs for packages that are platform-only.
 */
final class AdvisoryFetcher
{
    private const API_URL = 'https://packagist.org/api/security-advisories/';

    /**
     * Fetch advisory IDs for the given packages from the locked repository.
     *
     * When $filterByInstalledVersion is true, only advisories whose affectedVersions
     * constraint matches the installed version are returned. When false (default for
     * audit ignore injection), all advisories are returned so Composer's own version
     * matching can handle the filtering.
     *
     * @param list<string>        $packageNames            Package names to check
     * @param RepositoryInterface $repository              Locked repository with installed versions
     * @param bool                $filterByInstalledVersion Whether to filter by installed version
     *
     * @return array<string, string> Advisory ID → reason (for injection into audit.ignore)
     */
    public function fetchAdvisoryIds(
        array $packageNames,
        RepositoryInterface $repository,
        string $reason,
        bool $filterByInstalledVersion = false,
    ): array {
        if ($packageNames === []) {
            return [];
        }

        // Build installed version map for filtering
        $installedVersions = [];
        if ($filterByInstalledVersion) {
            foreach ($repository->getPackages() as $package) {
                $installedVersions[$package->getName()] = $package->getVersion();
            }
        }

        // Build API query
        $query = http_build_query(['packages' => $packageNames]);
        $url = self::API_URL . '?' . $query;

        $context = stream_context_create([
            'http' => [
                'timeout' => 10,
                'user_agent' => 'composer-audit-responsibility/0.1',
            ],
        ]);

        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            return [];
        }

        /** @var mixed $data */
        $data = json_decode($response, true);
        if (!\is_array($data) || !isset($data['advisories']) || !\is_array($data['advisories'])) {
            return [];
        }

        /** @var array<string, mixed> $advisories */
        $advisories = $data['advisories'];

        $result = [];
        foreach ($advisories as $packageName => $packageAdvisories) {
            if (!\is_string($packageName) || !\is_array($packageAdvisories)) {
                continue;
            }

            /** @var list<mixed> $packageAdvisories */
            foreach ($packageAdvisories as $advisory) {
                if (!\is_array($advisory)) {
                    continue;
                }

                $advisoryId = $advisory['advisoryId'] ?? $advisory['cve'] ?? null;
                if (!\is_string($advisoryId) || $advisoryId === '') {
                    continue;
                }

                // When filtering by installed version, skip advisories that don't
                // affect the installed version of this package.
                if ($filterByInstalledVersion) {
                    $affectedVersions = $advisory['affectedVersions'] ?? null;
                    $installedVersion = $installedVersions[$packageName] ?? null;

                    if (\is_string($affectedVersions) && \is_string($installedVersion)) {
                        try {
                            if (!Semver::satisfies($installedVersion, $affectedVersions)) {
                                continue;
                            }
                        } catch (\Throwable) {
                            // If constraint parsing fails, include the advisory conservatively
                        }
                    }
                }

                $result[$advisoryId] = $reason;
            }
        }

        return $result;
    }
}
