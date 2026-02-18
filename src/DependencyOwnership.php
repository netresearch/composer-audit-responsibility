<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility;

/**
 * Classification of a package's ownership in the dependency graph.
 */
enum DependencyOwnership: string
{
    /** Package is a direct dependency of the root project (user's responsibility). */
    case Direct = 'direct';

    /** Package is reachable only through platform/upstream packages. */
    case PlatformOnly = 'platform-only';

    /** Package is reachable through both user and platform dependency paths. */
    case Shared = 'shared';

    /** Package is reachable only through user's own transitive dependencies. */
    case UserTransitive = 'user-transitive';

    /**
     * Whether this package's security advisories should block installation.
     *
     * Direct, Shared, and UserTransitive all block because the user has
     * at least one dependency path they control.
     */
    public function shouldBlock(): bool
    {
        return $this !== self::PlatformOnly;
    }
}
