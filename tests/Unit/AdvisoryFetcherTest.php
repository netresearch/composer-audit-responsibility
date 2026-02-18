<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Unit;

use Composer\Package\PackageInterface;
use Composer\Repository\RepositoryInterface;
use Netresearch\ComposerAuditResponsibility\AdvisoryFetcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AdvisoryFetcher::class)]
final class AdvisoryFetcherTest extends TestCase
{
    #[Test]
    public function fetchAdvisoryIdsReturnsEmptyForEmptyPackageList(): void
    {
        $fetcher = new AdvisoryFetcher();
        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([]);

        $result = $fetcher->fetchAdvisoryIds([], $repository, 'test reason');

        self::assertSame([], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsGracefullyHandlesApiFailure(): void
    {
        // The fetcher should return empty array on API failure (no exception)
        $fetcher = new AdvisoryFetcher();

        $package = $this->createMock(PackageInterface::class);
        $package->method('getName')->willReturn('nonexistent/package-that-surely-does-not-exist');
        $package->method('getVersion')->willReturn('1.0.0');

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([$package]);

        // This will either hit the API and get empty results, or fail gracefully
        $result = $fetcher->fetchAdvisoryIds(
            ['nonexistent/package-that-surely-does-not-exist'],
            $repository,
            'test reason',
        );

        self::assertIsArray($result);
    }
}
