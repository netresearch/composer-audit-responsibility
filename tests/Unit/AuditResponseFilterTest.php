<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Unit;

use Netresearch\ComposerAuditResponsibility\AuditResponseFilter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuditResponseFilter::class)]
final class AuditResponseFilterTest extends TestCase
{
    private AuditResponseFilter $filter;

    protected function setUp(): void
    {
        $this->filter = new AuditResponseFilter();
    }

    #[Test]
    public function partitionSeparatesPlatformFromUserAdvisories(): void
    {
        $advisories = [
            'firebase/php-jwt' => [
                ['advisoryId' => 'PKSA-1234', 'title' => 'JWT vulnerability'],
            ],
            'my/library' => [
                ['advisoryId' => 'PKSA-5678', 'title' => 'Library vulnerability'],
            ],
        ];

        $result = $this->filter->partition($advisories, ['firebase/php-jwt']);

        self::assertArrayHasKey('firebase/php-jwt', $result['informational']);
        self::assertArrayHasKey('my/library', $result['blocking']);
        self::assertArrayNotHasKey('firebase/php-jwt', $result['blocking']);
        self::assertArrayNotHasKey('my/library', $result['informational']);
    }

    #[Test]
    public function partitionHandlesEmptyAdvisories(): void
    {
        $result = $this->filter->partition([], ['firebase/php-jwt']);

        self::assertSame([], $result['blocking']);
        self::assertSame([], $result['informational']);
    }

    #[Test]
    public function partitionHandlesEmptyPlatformPackages(): void
    {
        $advisories = [
            'my/library' => [
                ['advisoryId' => 'PKSA-5678', 'title' => 'Vulnerability'],
            ],
        ];

        $result = $this->filter->partition($advisories, []);

        self::assertArrayHasKey('my/library', $result['blocking']);
        self::assertSame([], $result['informational']);
    }

    #[Test]
    public function partitionHandlesMultipleAdvisoriesPerPackage(): void
    {
        $advisories = [
            'firebase/php-jwt' => [
                ['advisoryId' => 'PKSA-1111', 'title' => 'First vuln'],
                ['advisoryId' => 'PKSA-2222', 'title' => 'Second vuln'],
            ],
        ];

        $result = $this->filter->partition($advisories, ['firebase/php-jwt']);

        self::assertCount(2, $result['informational']['firebase/php-jwt']);
    }

    #[Test]
    public function getIgnorableAdvisoryIdsExtractsFromPlatformPackages(): void
    {
        $advisories = [
            'firebase/php-jwt' => [
                ['advisoryId' => 'PKSA-1234', 'title' => 'JWT vuln'],
                ['advisoryId' => 'PKSA-5678', 'title' => 'Another JWT vuln'],
            ],
            'my/library' => [
                ['advisoryId' => 'PKSA-9999', 'title' => 'User vuln'],
            ],
        ];

        $result = $this->filter->getIgnorableAdvisoryIds($advisories, ['firebase/php-jwt']);

        self::assertSame(['PKSA-1234', 'PKSA-5678'], $result);
    }

    #[Test]
    public function getIgnorableAdvisoryIdsFallsBackToCve(): void
    {
        $advisories = [
            'firebase/php-jwt' => [
                ['cve' => 'CVE-2024-1234', 'title' => 'JWT vuln'],
            ],
        ];

        $result = $this->filter->getIgnorableAdvisoryIds($advisories, ['firebase/php-jwt']);

        self::assertSame(['CVE-2024-1234'], $result);
    }

    #[Test]
    public function getIgnorableAdvisoryIdsDeduplicates(): void
    {
        $advisories = [
            'firebase/php-jwt' => [
                ['advisoryId' => 'PKSA-1234', 'title' => 'First'],
            ],
            'another/platform-dep' => [
                ['advisoryId' => 'PKSA-1234', 'title' => 'Same advisory'],
            ],
        ];

        $result = $this->filter->getIgnorableAdvisoryIds(
            $advisories,
            ['firebase/php-jwt', 'another/platform-dep'],
        );

        self::assertSame(['PKSA-1234'], $result);
    }

    #[Test]
    public function getIgnorableAdvisoryIdsSkipsMissingIds(): void
    {
        $advisories = [
            'firebase/php-jwt' => [
                ['title' => 'No ID advisory'],
                ['advisoryId' => '', 'title' => 'Empty ID'],
                ['advisoryId' => 'PKSA-1234', 'title' => 'Has ID'],
            ],
        ];

        $result = $this->filter->getIgnorableAdvisoryIds($advisories, ['firebase/php-jwt']);

        self::assertSame(['PKSA-1234'], $result);
    }
}
