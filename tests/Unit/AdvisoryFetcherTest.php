<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Unit;

use Composer\Package\PackageInterface;
use Composer\Repository\RepositoryInterface;
use Netresearch\ComposerAuditResponsibility\AdvisoryFetcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Testable subclass that overrides fetchJson to return canned responses.
 */
class TestableAdvisoryFetcher extends AdvisoryFetcher
{
    /**
     * @param array<string, mixed>|null $cannedResponse
     */
    public function __construct(private ?array $cannedResponse) {}

    protected function fetchJson(string $url): ?array
    {
        return $this->cannedResponse;
    }
}

#[CoversClass(AdvisoryFetcher::class)]
final class AdvisoryFetcherTest extends TestCase
{
    #[Test]
    public function fetchAdvisoryIdsReturnsEmptyForEmptyPackageList(): void
    {
        $fetcher = new TestableAdvisoryFetcher(null);
        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([]);

        $result = $fetcher->fetchAdvisoryIds([], $repository, 'test reason');

        self::assertSame([], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsReturnsAdvisoriesForPackage(): void
    {
        $fetcher = new TestableAdvisoryFetcher([
            'advisories' => [
                'vendor/package' => [
                    [
                        'advisoryId' => 'PKSA-1234',
                        'affectedVersions' => '>=1.0,<1.5',
                    ],
                ],
            ],
        ]);

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([]);

        $result = $fetcher->fetchAdvisoryIds(['vendor/package'], $repository, 'test reason');

        self::assertSame(['PKSA-1234' => 'test reason'], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsExtractsCveWhenNoAdvisoryId(): void
    {
        $fetcher = new TestableAdvisoryFetcher([
            'advisories' => [
                'vendor/package' => [
                    [
                        'cve' => 'CVE-2026-0001',
                        'affectedVersions' => '>=1.0,<2.0',
                    ],
                ],
            ],
        ]);

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([]);

        $result = $fetcher->fetchAdvisoryIds(['vendor/package'], $repository, 'platform dep');

        self::assertSame(['CVE-2026-0001' => 'platform dep'], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsSkipsEmptyAdvisoryIds(): void
    {
        $fetcher = new TestableAdvisoryFetcher([
            'advisories' => [
                'vendor/package' => [
                    ['affectedVersions' => '>=1.0,<2.0'],
                    ['advisoryId' => '', 'cve' => ''],
                    ['advisoryId' => null],
                ],
            ],
        ]);

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([]);

        $result = $fetcher->fetchAdvisoryIds(['vendor/package'], $repository, 'test');

        self::assertSame([], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsFiltersMatchingVersion(): void
    {
        $fetcher = new TestableAdvisoryFetcher([
            'advisories' => [
                'vendor/package' => [
                    [
                        'advisoryId' => 'PKSA-match',
                        'affectedVersions' => '>=1.0,<2.0',
                    ],
                ],
            ],
        ]);

        $package = $this->createMock(PackageInterface::class);
        $package->method('getName')->willReturn('vendor/package');
        $package->method('getVersion')->willReturn('1.5.0');

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([$package]);

        $result = $fetcher->fetchAdvisoryIds(
            ['vendor/package'],
            $repository,
            'test',
            filterByInstalledVersion: true,
        );

        self::assertSame(['PKSA-match' => 'test'], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsExcludesNonMatchingVersion(): void
    {
        $fetcher = new TestableAdvisoryFetcher([
            'advisories' => [
                'vendor/package' => [
                    [
                        'advisoryId' => 'PKSA-nomatch',
                        'affectedVersions' => '>=1.0,<2.0',
                    ],
                ],
            ],
        ]);

        $package = $this->createMock(PackageInterface::class);
        $package->method('getName')->willReturn('vendor/package');
        $package->method('getVersion')->willReturn('3.0.0');

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([$package]);

        $result = $fetcher->fetchAdvisoryIds(
            ['vendor/package'],
            $repository,
            'test',
            filterByInstalledVersion: true,
        );

        self::assertSame([], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsIncludesAllWhenFilterDisabled(): void
    {
        $fetcher = new TestableAdvisoryFetcher([
            'advisories' => [
                'vendor/package' => [
                    [
                        'advisoryId' => 'PKSA-all',
                        'affectedVersions' => '>=1.0,<2.0',
                    ],
                ],
            ],
        ]);

        $package = $this->createMock(PackageInterface::class);
        $package->method('getName')->willReturn('vendor/package');
        $package->method('getVersion')->willReturn('3.0.0');

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([$package]);

        $result = $fetcher->fetchAdvisoryIds(
            ['vendor/package'],
            $repository,
            'test',
            filterByInstalledVersion: false,
        );

        self::assertSame(['PKSA-all' => 'test'], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsHandlesMalformedResponse(): void
    {
        // Missing 'advisories' key
        $fetcher = new TestableAdvisoryFetcher(['status' => 'ok']);

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([]);

        $result = $fetcher->fetchAdvisoryIds(['vendor/package'], $repository, 'test');

        self::assertSame([], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsHandlesNonArrayAdvisories(): void
    {
        $fetcher = new TestableAdvisoryFetcher([
            'advisories' => [
                'vendor/package' => 'not-an-array',
            ],
        ]);

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([]);

        $result = $fetcher->fetchAdvisoryIds(['vendor/package'], $repository, 'test');

        self::assertSame([], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsIncludesOnConstraintParseError(): void
    {
        $fetcher = new TestableAdvisoryFetcher([
            'advisories' => [
                'vendor/package' => [
                    [
                        'advisoryId' => 'PKSA-bad-constraint',
                        'affectedVersions' => 'INVALID_CONSTRAINT!!!',
                    ],
                ],
            ],
        ]);

        $package = $this->createMock(PackageInterface::class);
        $package->method('getName')->willReturn('vendor/package');
        $package->method('getVersion')->willReturn('1.0.0');

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([$package]);

        // With filterByInstalledVersion=true and a bad constraint, it should
        // include the advisory conservatively (catch block)
        $result = $fetcher->fetchAdvisoryIds(
            ['vendor/package'],
            $repository,
            'test',
            filterByInstalledVersion: true,
        );

        self::assertSame(['PKSA-bad-constraint' => 'test'], $result);
    }

    #[Test]
    public function fetchAdvisoryIdsReturnsEmptyOnApiFailure(): void
    {
        // null response simulates API failure
        $fetcher = new TestableAdvisoryFetcher(null);

        $repository = $this->createMock(RepositoryInterface::class);
        $repository->method('getPackages')->willReturn([]);

        $result = $fetcher->fetchAdvisoryIds(['vendor/package'], $repository, 'test');

        self::assertSame([], $result);
    }
}
