<?php

declare(strict_types=1);

namespace Netresearch\ComposerAuditResponsibility\Tests\Unit;

use Composer\Composer;
use Composer\Config;
use Composer\IO\BufferIO;
use Composer\Package\Link;
use Composer\Package\Locker;
use Composer\Package\Package;
use Composer\Package\RootPackage;
use Composer\Plugin\PreCommandRunEvent;
use Composer\Policy\PolicyConfig;
use Composer\Repository\LockArrayRepository;
use Composer\Script\Event as ScriptEvent;
use Composer\Semver\Constraint\MatchAllConstraint;
use Netresearch\ComposerAuditResponsibility\AdvisoryFetcher;
use Netresearch\ComposerAuditResponsibility\Plugin;
use Netresearch\ComposerAuditResponsibility\RootIgnoreFilter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The post-install audit must honour the root project's own advisory ignore
 * configuration (config.audit.ignore and config.policy.advisories) the way
 * Composer does when it blocks, and must keep blocking everything else.
 *
 * Advisory data is a verbatim excerpt of the Packagist security-advisories API
 * (tests/Fixtures/packagist-advisories.json); installed versions are those of
 * the project that exposed the defect (TYPO3 12.4.45, evoweb/sf-register 12.0.1).
 */
#[CoversClass(Plugin::class)]
#[CoversClass(RootIgnoreFilter::class)]
final class RootIgnoreConfigTest extends TestCase
{
    private const SF_REGISTER = 'PKSA-1gw5-qx8s-xyvr';
    private const CMS_CORE = 'PKSA-2yr3-by9d-r1gh';
    private const CMS_BACKEND = 'PKSA-745m-816f-bzfy';
    private const PHP_JWT = 'PKSA-y2cr-5h3j-g3ys';

    /** Only evoweb/sf-register 12.0.1 is affected; TYPO3 12.4.49 has no open advisory in the fixture */
    private const SF_REGISTER_VULNERABLE = [
        'typo3/cms-core' => '12.4.49.0',
        'typo3/cms-backend' => '12.4.49.0',
        'evoweb/sf-register' => '12.0.1.0',
    ];

    /** TYPO3 12.4.45 as in the reported project: one advisory each for cms-core and cms-backend */
    private const CORE_VULNERABLE = [
        'typo3/cms-core' => '12.4.45.0',
        'typo3/cms-backend' => '12.4.45.0',
    ];

    protected function tearDown(): void
    {
        unset($_SERVER['COMPOSER_NO_SECURITY_BLOCKING']);
        putenv('COMPOSER_NO_SECURITY_BLOCKING');
    }

    #[Test]
    public function advisoryIdInAuditIgnoreDoesNotBlock(): void
    {
        $output = $this->assertInstallPasses(
            ['audit' => ['ignore' => [self::SF_REGISTER => 'mitigated via root patch']]],
            self::SF_REGISTER_VULNERABLE,
        );

        self::assertStringContainsString(self::SF_REGISTER . ' (evoweb/sf-register): mitigated via root patch', $output);
    }

    #[Test]
    public function cveInAuditIgnoreDoesNotBlock(): void
    {
        $output = $this->assertInstallPasses(
            ['audit' => ['ignore' => ['CVE-2026-46721']]],
            self::SF_REGISTER_VULNERABLE,
        );

        self::assertStringContainsString(self::SF_REGISTER . ' (evoweb/sf-register)', $output);
    }

    #[Test]
    public function packageNameInPolicyAdvisoriesIgnoreDoesNotBlock(): void
    {
        $output = $this->assertInstallPasses(
            ['policy' => ['advisories' => ['ignore' => [
                'typo3/cms-core' => 'No patched 12.4 release',
                'typo3/cms-backend' => 'See typo3/cms-core',
            ]]]],
            self::CORE_VULNERABLE,
        );

        self::assertStringContainsString(self::CMS_CORE . ' (typo3/cms-core): No patched 12.4 release', $output);
        self::assertStringContainsString(self::CMS_BACKEND . ' (typo3/cms-backend): See typo3/cms-core', $output);
    }

    #[Test]
    public function remoteIdInPolicyAdvisoriesIgnoreIdDoesNotBlock(): void
    {
        $output = $this->assertInstallPasses(
            ['policy' => ['advisories' => ['ignore-id' => ['GHSA-v348-vr4q-fv9p' => 'GHSA accepted']]]],
            self::SF_REGISTER_VULNERABLE,
        );

        self::assertStringContainsString(self::SF_REGISTER . ' (evoweb/sf-register): GHSA accepted', $output);
    }

    #[Test]
    public function projectConfigurationOfTheReportedCaseDoesNotBlock(): void
    {
        // config section of mfag/cms/nrc-template-mfag composer.json, verbatim
        $output = $this->assertInstallPasses(
            [
                'audit' => ['ignore' => [
                    'PKSA-y2cr-5h3j-g3ys' => 'firebase/php-jwt - framework dep',
                    'PKSA-1gw5-qx8s-xyvr' => 'evoweb/sf-register - TYPO3-EXT-SA-2026-009, mitigated via root patch (no fixed 12.x release upstream)',
                ]],
                'policy' => ['advisories' => ['ignore' => [
                    'typo3/cms-core' => 'No patched 12.4 release for the current advisory wave; mitigated project-side, revisit on core update',
                    'typo3/cms-backend' => 'See typo3/cms-core',
                    'evoweb/sf-register' => 'No fixed 12.x release upstream (TYPO3-EXT-SA-2026-009); already whitelisted in audit.ignore',
                ]]],
            ],
            self::CORE_VULNERABLE + self::SF_REGISTER_VULNERABLE,
        );

        self::assertStringContainsString('Ignored 3 advisory/ies', $output);
    }

    #[Test]
    public function advisoryNotCoveredByTheIgnoreConfigurationStillBlocks(): void
    {
        [$exception, $output] = $this->runInstall(
            ['audit' => ['ignore' => [self::SF_REGISTER => 'accepted']]],
            ['typo3/cms-core' => '12.4.45.0'] + self::SF_REGISTER_VULNERABLE,
        );

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertStringContainsString('1 security advisory/ies found', $exception->getMessage());
        self::assertStringContainsString('- ' . self::CMS_CORE, $output);
        self::assertStringContainsString(self::SF_REGISTER . ' (evoweb/sf-register): accepted', $output);
    }

    #[Test]
    public function auditOnlyIgnoreStillBlocks(): void
    {
        [$exception] = $this->runInstall(
            ['audit' => ['ignore' => [self::SF_REGISTER => ['apply' => 'audit', 'reason' => 'report only']]]],
            self::SF_REGISTER_VULNERABLE,
        );

        self::assertInstanceOf(\RuntimeException::class, $exception);
    }

    #[Test]
    public function ignoreIdWithOnBlockFalseStillBlocks(): void
    {
        [$exception] = $this->runInstall(
            ['policy' => ['advisories' => ['ignore-id' => [self::SF_REGISTER => ['on-block' => false]]]]],
            self::SF_REGISTER_VULNERABLE,
        );

        self::assertInstanceOf(\RuntimeException::class, $exception);
    }

    #[Test]
    public function auditIgnoreIsNotReadWhenPolicyAdvisoriesIsSet(): void
    {
        // Composer reads the legacy audit.ignore only when policy.advisories is absent.
        [$exception, $output] = $this->runInstall(
            [
                'audit' => ['ignore' => [self::SF_REGISTER => 'accepted']],
                'policy' => ['advisories' => ['ignore' => ['typo3/cms-core' => 'accepted']]],
            ],
            ['typo3/cms-core' => '12.4.45.0'] + self::SF_REGISTER_VULNERABLE,
        );

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertStringContainsString('- ' . self::SF_REGISTER, $output);
        self::assertStringContainsString(self::CMS_CORE . ' (typo3/cms-core): accepted', $output);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function advisoryBlockingDisabledProvider(): iterable
    {
        yield 'policy: false' => [['policy' => false]];
        yield 'policy.advisories: false' => [['policy' => ['advisories' => false]]];
        yield 'policy.advisories.block: false' => [['policy' => ['advisories' => ['block' => false]]]];
        yield 'audit.block-insecure: false (no policy.advisories)' => [['audit' => ['block-insecure' => false]]];
    }

    /**
     * @param array<string, mixed> $projectConfig
     */
    #[Test]
    #[DataProvider('advisoryBlockingDisabledProvider')]
    public function projectThatDisablesAdvisoryBlockingIsReportedNotBlocked(array $projectConfig): void
    {
        $output = $this->assertInstallPasses($projectConfig, self::SF_REGISTER_VULNERABLE);

        self::assertStringContainsString('Found 1 security advisory/ies in YOUR dependencies; not blocking', $output);
        self::assertStringContainsString('- ' . self::SF_REGISTER, $output);
    }

    #[Test]
    public function policyAdvisoriesBlockTrueStillBlocks(): void
    {
        [$exception] = $this->runInstall(
            ['policy' => ['advisories' => ['block' => true]], 'audit' => ['block-insecure' => false]],
            self::SF_REGISTER_VULNERABLE,
        );

        self::assertInstanceOf(\RuntimeException::class, $exception);
    }

    // `composer audit`: platform-only advisories are injected as ignores where Composer reads them

    #[Test]
    public function auditInjectionLandsInThePolicyListWhenPolicyAdvisoriesIsSet(): void
    {
        $config = $this->runAudit(['policy' => ['advisories' => ['ignore' => ['typo3/cms-core' => 'accepted']]]]);

        $auditIgnores = PolicyConfig::fromConfig($config)->advisories->getIgnoreListForOperation('audit');
        self::assertArrayHasKey(self::PHP_JWT, $auditIgnores);
        self::assertStringContainsString('Platform dependency via typo3/cms-core', (string) $auditIgnores[self::PHP_JWT]);
        self::assertSame('accepted', $auditIgnores['typo3/cms-core']);
        self::assertArrayNotHasKey(
            self::PHP_JWT,
            PolicyConfig::fromConfig($config)->advisories->getIgnoreListForOperation('block'),
            'injected for the audit only',
        );
    }

    #[Test]
    public function auditInjectionKeepsTheProjectsOwnReasonForTheSameId(): void
    {
        $config = $this->runAudit(['policy' => ['advisories' => ['ignore-id' => [self::PHP_JWT => 'project reason']]]]);

        self::assertSame(
            'project reason',
            PolicyConfig::fromConfig($config)->advisories->getIgnoreListForOperation('audit')[self::PHP_JWT] ?? null,
        );
    }

    #[Test]
    public function auditInjectionStillUsesAuditIgnoreWithoutPolicyAdvisories(): void
    {
        $config = $this->runAudit([]);

        self::assertArrayHasKey(self::PHP_JWT, PolicyConfig::fromConfig($config)->advisories->getIgnoreListForOperation('audit'));
    }

    #[Test]
    public function auditInjectionDoesNotReEnableADisabledAdvisoryPolicy(): void
    {
        $config = $this->runAudit(['policy' => ['advisories' => false]]);

        $advisories = PolicyConfig::fromConfig($config)->advisories;
        self::assertSame('ignore', $advisories->audit);
        self::assertFalse($advisories->block);
    }

    // Fallback used when Composer has no PolicyConfig (Composer < 2.10)

    #[Test]
    public function legacyFallbackHonoursIdCvePackageAndSeverity(): void
    {
        $advisories = $this->fixtureAdvisories();

        $partition = $this->legacyFilter(['ignore' => [
            self::SF_REGISTER => 'by id',
            'CVE-2026-11607' => 'by cve',
            'typo3/cms-backend' => 'by package',
        ]])->partition($advisories);

        self::assertSame(['PKSA-y2cr-5h3j-g3ys' => 'firebase/php-jwt'], $partition['blocking']);
        self::assertEqualsCanonicalizing([
            ['id' => self::CMS_CORE, 'package' => 'typo3/cms-core', 'reason' => 'by cve'],
            ['id' => self::CMS_BACKEND, 'package' => 'typo3/cms-backend', 'reason' => 'by package'],
            ['id' => self::SF_REGISTER, 'package' => 'evoweb/sf-register', 'reason' => 'by id'],
        ], $partition['ignored']);

        $bySeverity = $this->legacyFilter(['ignore-severity' => ['low']])->partition($advisories);
        self::assertArrayNotHasKey('PKSA-y2cr-5h3j-g3ys', $bySeverity['blocking']);
        self::assertCount(3, $bySeverity['blocking']);
    }

    #[Test]
    public function legacyFallbackKeepsAuditOnlyEntriesBlocking(): void
    {
        $partition = $this->legacyFilter(['ignore' => [
            self::SF_REGISTER => ['apply' => 'audit'],
            'GHSA-pjpj-v387-x4vq' => ['apply' => 'block', 'reason' => 'by remote id'],
        ]])->partition($this->fixtureAdvisories());

        self::assertArrayHasKey(self::SF_REGISTER, $partition['blocking']);
        self::assertSame(
            [['id' => self::CMS_CORE, 'package' => 'typo3/cms-core', 'reason' => 'by remote id']],
            $partition['ignored'],
        );
    }

    #[Test]
    public function legacyFallbackReadsBlockInsecure(): void
    {
        self::assertTrue($this->legacyFilter([])->blocksAdvisories());
        self::assertFalse($this->legacyFilter(['block-insecure' => false])->blocksAdvisories());
    }

    // ──────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────

    /**
     * @param array<string, mixed>  $projectConfig "config" section of the root composer.json
     * @param array<string, string> $installed     Package name => normalized version, all required directly
     */
    private function assertInstallPasses(array $projectConfig, array $installed): string
    {
        [$exception, $output] = $this->runInstall($projectConfig, $installed);
        if ($exception !== null) {
            self::fail('Install was blocked: ' . $exception->getMessage() . "\n" . $output);
        }

        return $output;
    }

    /**
     * Run the plugin through install: pre-command, then post-install audit.
     *
     * @param array<string, mixed>  $projectConfig
     * @param array<string, string> $installed     Package name => normalized version, all required directly
     *
     * @return array{0: \RuntimeException|null, 1: string}
     */
    private function runInstall(array $projectConfig, array $installed): array
    {
        $config = new Config(false);
        $config->merge(['config' => $projectConfig]);

        $rootPackage = new RootPackage('my/site', '1.0.0.0', '1.0.0');
        $rootPackage->setType('typo3-cms-extension');
        $links = [];
        $packages = [];
        foreach ($installed as $name => $version) {
            $links[$name] = new Link('my/site', $name, new MatchAllConstraint(), Link::TYPE_REQUIRE, '*');
            $packages[] = new Package($name, $version, $version);
        }
        $rootPackage->setRequires($links);

        $locker = $this->createStub(Locker::class);
        $locker->method('isLocked')->willReturn(true);
        $locker->method('getLockedRepository')->willReturn(new LockArrayRepository($packages));

        $composer = $this->createStub(Composer::class);
        $composer->method('getPackage')->willReturn($rootPackage);
        $composer->method('getLocker')->willReturn($locker);
        $composer->method('getConfig')->willReturn($config);

        $io = new BufferIO();
        $plugin = $this->createFixturePlugin();
        $plugin->activate($composer, $io);

        $preEvent = $this->createStub(PreCommandRunEvent::class);
        $preEvent->method('getCommand')->willReturn('install');
        $plugin->onPreCommandRun($preEvent);

        $postEvent = $this->createStub(ScriptEvent::class);
        $postEvent->method('getComposer')->willReturn($composer);
        $postEvent->method('getIO')->willReturn($io);

        $exception = null;
        try {
            $plugin->onPostInstall($postEvent);
        } catch (\RuntimeException $e) {
            $exception = $e;
        }

        return [$exception, $io->getOutput()];
    }

    /**
     * Run the plugin's pre-command hook for `composer audit` on a project whose
     * locked firebase/php-jwt 6.11.1 is reachable only through typo3/cms-core.
     *
     * @param array<string, mixed> $projectConfig
     */
    private function runAudit(array $projectConfig): Config
    {
        $config = new Config(false);
        $config->merge(['config' => $projectConfig]);

        $rootPackage = new RootPackage('my/site', '1.0.0.0', '1.0.0');
        $rootPackage->setType('typo3-cms-extension');
        $rootPackage->setRequires([
            'typo3/cms-core' => new Link('my/site', 'typo3/cms-core', new MatchAllConstraint(), Link::TYPE_REQUIRE, '*'),
        ]);

        $core = new Package('typo3/cms-core', '12.4.49.0', '12.4.49');
        $core->setRequires([
            'firebase/php-jwt' => new Link('typo3/cms-core', 'firebase/php-jwt', new MatchAllConstraint(), Link::TYPE_REQUIRE, '*'),
        ]);

        $locker = $this->createStub(Locker::class);
        $locker->method('isLocked')->willReturn(true);
        $locker->method('getLockedRepository')->willReturn(new LockArrayRepository([
            $core,
            new Package('firebase/php-jwt', '6.11.1.0', 'v6.11.1'),
        ]));

        $composer = $this->createStub(Composer::class);
        $composer->method('getPackage')->willReturn($rootPackage);
        $composer->method('getLocker')->willReturn($locker);
        $composer->method('getConfig')->willReturn($config);

        $plugin = $this->createFixturePlugin();
        $plugin->activate($composer, new BufferIO());

        $preEvent = $this->createStub(PreCommandRunEvent::class);
        $preEvent->method('getCommand')->willReturn('audit');
        $plugin->onPreCommandRun($preEvent);

        return $config;
    }

    /**
     * Plugin whose advisory fetcher answers from the Packagist fixture.
     */
    private function createFixturePlugin(): Plugin
    {
        $fixture = $this->fixturePayload();
        return new class ($fixture) extends Plugin {
            /** @param array<string, mixed> $fixture */
            public function __construct(private array $fixture) {}

            protected function createAdvisoryFetcher(): AdvisoryFetcher
            {
                $fixture = $this->fixture;

                return new class ($fixture) extends AdvisoryFetcher {
                    /** @param array<string, mixed> $fixture */
                    public function __construct(private array $fixture) {}

                    protected function fetchJson(string $url): ?array
                    {
                        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);
                        $requested = \is_array($query['packages'] ?? null) ? $query['packages'] : [];
                        $advisories = \is_array($this->fixture['advisories'] ?? null) ? $this->fixture['advisories'] : [];

                        return ['advisories' => array_intersect_key($advisories, array_flip($requested))];
                    }
                };
            }
        };
    }

    /**
     * @param array<string, mixed> $auditConfig "config.audit" section
     */
    private function legacyFilter(array $auditConfig): RootIgnoreFilter
    {
        $config = new Config(false);
        $config->merge(['config' => ['audit' => $auditConfig]]);

        return RootIgnoreFilter::fromConfig($config, usePolicyConfig: false);
    }

    /**
     * @return array<string, mixed>
     */
    private function fixturePayload(): array
    {
        $data = json_decode((string) file_get_contents(__DIR__ . '/../Fixtures/packagist-advisories.json'), true);
        self::assertIsArray($data);

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * @return array<string, list<array<mixed>>>
     */
    private function fixtureAdvisories(): array
    {
        /** @var array<string, list<array<mixed>>> $advisories */
        $advisories = $this->fixturePayload()['advisories'];

        return $advisories;
    }
}
