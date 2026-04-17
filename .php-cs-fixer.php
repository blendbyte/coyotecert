<?php

$finder = PhpCsFixer\Finder::create()
    ->in([__DIR__ . '/src', __DIR__ . '/tests'])
    ->name('*.php');

return (new PhpCsFixer\Config())
    ->setRules([
        '@PER-CS'                             => true,
        '@PHP83Migration'                     => true,
        'array_syntax'                        => ['syntax' => 'short'],
        'ordered_imports'                     => ['sort_algorithm' => 'alpha'],
        'no_unused_imports'                   => true,
        'single_quote'                        => true,
        'trailing_comma_in_multiline'         => ['elements' => ['arrays', 'arguments', 'parameters']],
        'binary_operator_spaces'              => ['default' => 'align_single_space_minimal'],
        'concat_space'                        => ['spacing' => 'one'],
        'blank_line_before_statement'         => ['statements' => ['return', 'throw']],
        'method_chaining_indentation'         => true,
        'no_extra_blank_lines'                => true,
        'phpdoc_align'                        => ['align' => 'left'],
        'phpdoc_no_empty_return'              => true,
        'phpdoc_scalar'                       => true,
        'phpdoc_trim'                         => true,
    ])
    ->setFinder($finder)
    ->setCacheFile(__DIR__ . '/.php-cs-fixer.cache');
