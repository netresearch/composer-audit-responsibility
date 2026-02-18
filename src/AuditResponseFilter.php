<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

/**
 * Filters security advisory responses to separate platform-owned from user-owned advisories.
 *
 * This is used to post-process audit results: platform-only advisories are reported
 * as informational warnings rather than blocking errors.
 */
final class AuditResponseFilter
{
    /**
     * Partition advisories into blocking and informational sets.
     *
     * @param array<string, list<array<string, mixed>>> $advisories Package name → list of advisories
     * @param list<string>                              $platformOnlyPackages
     *
     * @return array{blocking: array<string, list<array<string, mixed>>>, informational: array<string, list<array<string, mixed>>>}
     */
    public function partition(array $advisories, array $platformOnlyPackages): array
    {
        $platformSet = array_flip($platformOnlyPackages);
        $blocking = [];
        $informational = [];

        foreach ($advisories as $packageName => $packageAdvisories) {
            if (isset($platformSet[$packageName])) {
                $informational[$packageName] = $packageAdvisories;
            } else {
                $blocking[$packageName] = $packageAdvisories;
            }
        }

        return [
            'blocking' => $blocking,
            'informational' => $informational,
        ];
    }

    /**
     * Get the list of advisory IDs that should be ignored for blocking purposes.
     *
     * @param array<string, list<array<string, mixed>>> $advisories
     * @param list<string>                              $platformOnlyPackages
     *
     * @return list<string> Advisory IDs to ignore
     */
    public function getIgnorableAdvisoryIds(array $advisories, array $platformOnlyPackages): array
    {
        $platformSet = array_flip($platformOnlyPackages);
        $ids = [];

        foreach ($advisories as $packageName => $packageAdvisories) {
            if (!isset($platformSet[$packageName])) {
                continue;
            }

            foreach ($packageAdvisories as $advisory) {
                $id = $advisory['advisoryId'] ?? $advisory['cve'] ?? null;
                if (\is_string($id) && $id !== '') {
                    $ids[] = $id;
                }
            }
        }

        return array_values(array_unique($ids));
    }
}
