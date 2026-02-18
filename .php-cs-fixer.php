<?php

$finder = (new PhpCsFixer\Finder())
    ->in(__DIR__ . '/src')
    ->in(__DIR__ . '/tests');

return (new PhpCsFixer\Config())
    ->setRules([
        '@PER-CS2.0' => true,
        'declare_strict_types' => true,
        'no_unused_imports' => true,
        'ordered_imports' => ['sort_algorithm' => 'alpha'],
        'trailing_comma_in_multiline' => ['elements' => ['arguments', 'arrays', 'parameters']],
    ])
    ->setFinder($finder)
    ->setRiskyAllowed(true)
    ->setUnsupportedPhpVersionAllowed(true);
