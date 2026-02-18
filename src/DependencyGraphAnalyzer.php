<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

use Composer\Package\PackageInterface;
use Composer\Repository\RepositoryInterface;

/**
 * Analyzes the dependency graph to classify package ownership.
 *
 * Walks the installed package repository using BFS from two starting sets:
 * 1. Platform roots (framework packages) → marks platform-reachable packages
 * 2. User roots (direct deps minus platform) → marks user-reachable packages
 *    User BFS treats platform packages as opaque barriers — it does NOT traverse into them.
 *
 * The intersection determines shared ownership; the difference determines
 * platform-only packages whose advisories should not block installation.
 */
final class DependencyGraphAnalyzer
{
    /**
     * Classify all installed packages by their ownership.
     *
     * @param RepositoryInterface  $repository     Installed/locked package repository
     * @param list<string>         $platformRoots  Package names identified as platform packages
     * @param list<string>         $directRequires Package names from root require (excluding platform roots)
     *
     * @return array<string, DependencyOwnership> Package name → ownership classification
     */
    public function classify(
        RepositoryInterface $repository,
        array $platformRoots,
        array $directRequires,
    ): array {
        $packageMap = $this->buildPackageMap($repository);

        // Separate user roots: direct requires minus platform roots
        $platformRootSet = array_flip($platformRoots);
        $userRoots = array_values(array_filter(
            $directRequires,
            static fn (string $name): bool => !isset($platformRootSet[$name]),
        ));

        // BFS from platform roots → all platform-reachable packages
        $platformReachable = $this->bfs($packageMap, $platformRoots);

        // BFS from user roots, but do NOT traverse INTO platform packages.
        // This prevents user deps like "my/lib → guzzle" from also reaching
        // framework transitive deps when user/platform share a dependency.
        $userReachable = $this->bfs($packageMap, $userRoots, $platformRootSet);

        // Classify each installed package
        $result = [];
        foreach ($packageMap as $name => $_package) {
            $inPlatform = isset($platformReachable[$name]);
            $inUser = isset($userReachable[$name]);
            $isDirect = \in_array($name, $directRequires, true);

            if ($isDirect) {
                $result[$name] = DependencyOwnership::Direct;
            } elseif ($inPlatform && $inUser) {
                $result[$name] = DependencyOwnership::Shared;
            } elseif ($inPlatform) {
                $result[$name] = DependencyOwnership::PlatformOnly;
            } elseif ($inUser) {
                $result[$name] = DependencyOwnership::UserTransitive;
            }
            // Packages not reachable from either set are orphaned; skip them
        }

        // Also classify platform roots themselves as Direct (user declared them)
        foreach ($platformRoots as $root) {
            if (isset($packageMap[$root])) {
                $result[$root] = DependencyOwnership::Direct;
            }
        }

        return $result;
    }

    /**
     * Get only the platform-only packages (those whose advisories should NOT block).
     *
     * @param list<string> $platformRoots
     * @param list<string> $directRequires
     *
     * @return list<string>
     */
    public function getPlatformOnlyPackages(
        RepositoryInterface $repository,
        array $platformRoots,
        array $directRequires,
    ): array {
        $classifications = $this->classify($repository, $platformRoots, $directRequires);

        $result = [];
        foreach ($classifications as $name => $ownership) {
            if ($ownership === DependencyOwnership::PlatformOnly) {
                $result[] = $name;
            }
        }

        return $result;
    }

    /**
     * BFS traversal from a set of root package names.
     *
     * @param array<string, PackageInterface> $packageMap
     * @param list<string>                    $roots
     * @param array<string, int>              $barriers Package names to NOT traverse into (visited but not expanded)
     *
     * @return array<string, true> Set of reachable package names
     */
    private function bfs(array $packageMap, array $roots, array $barriers = []): array
    {
        $visited = [];
        $queue = new \SplQueue();

        foreach ($roots as $root) {
            $queue->enqueue($root);
        }

        while (!$queue->isEmpty()) {
            /** @var string $current */
            $current = $queue->dequeue();

            if (isset($visited[$current])) {
                continue;
            }

            $visited[$current] = true;

            // If this package is a barrier, mark it as visited but don't expand its deps
            if (isset($barriers[$current])) {
                continue;
            }

            $package = $packageMap[$current] ?? null;
            if ($package === null) {
                continue;
            }

            foreach ($package->getRequires() as $link) {
                $target = $link->getTarget();

                // Skip PHP extensions and virtual packages
                if (!str_contains($target, '/')) {
                    continue;
                }

                if (!isset($visited[$target])) {
                    $queue->enqueue($target);
                }
            }
        }

        return $visited;
    }

    /**
     * @return array<string, PackageInterface>
     */
    private function buildPackageMap(RepositoryInterface $repository): array
    {
        $map = [];
        foreach ($repository->getPackages() as $package) {
            $map[$package->getName()] = $package;
        }

        return $map;
    }
}
