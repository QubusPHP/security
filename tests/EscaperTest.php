<?php

declare(strict_types=1);

use Qubus\EventDispatcher\ActionFilter\Observer;
use Qubus\Security\Escaper;

it('escapes HTML text using UTF-8 and HTML5 entities', function (): void {
    $escaped = new Escaper()->html('<tag title="x">Tom & Jerry\'s</tag>');

    expect($escaped)->toBe('&lt;tag title=&quot;x&quot;&gt;Tom &amp; Jerry&apos;s&lt;/tag&gt;');
});

it('prevents a textarea closing-tag injection', function (): void {
    $escaped = new Escaper()->textarea('</textarea><script>alert(1)</script>');

    expect($escaped)->toBe('&lt;/textarea&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
});

it('escapes both quote types in ordinary quoted attributes', function (): void {
    $escaped = new Escaper()->attr('" onfocus="alert(1)\'');

    expect($escaped)->toBe('&quot; onfocus=&quot;alert(1)&apos;');
});

it('scrubs invalid UTF-8 before escaping it', function (): void {
    $escaped = new Escaper()->html("valid\xC0<script>");

    expect($escaped)
        ->toStartWith('valid')
        ->toEndWith('&lt;script&gt;')
        ->not->toContain('<script>');
});

it('keeps UTF-8 and forced double encoding when filters return unsafe values', function (): void {
    $observer = new Observer();
    $observer->filter->addFilter(
        'escaper.character.encoding',
        static fn (mixed $value): array => [],
        arguments: 1
    );
    $observer->filter->addFilter(
        'escaper.double.encoding',
        static fn (mixed $value): bool => false,
        arguments: 1
    );

    try {
        $escaper = new Escaper();

        expect($escaper->html('<'))->toBe('&lt;')
            ->and($escaper->js('&#39;alert(1)'))->toBe('&amp;#39;alert(1)');
    } finally {
        $observer->filter->removeAllFilters('escaper.character.encoding');
        $observer->filter->removeAllFilters('escaper.double.encoding');
    }
});

it('preserves a valid URL without decoding its path delimiters', function (): void {
    $escaped = new Escaper()->url('https://example.com/path%2Fadmin');

    expect($escaped)->toBe('https://example.com/path%2Fadmin');
});

it('escapes query separators for a quoted HTML attribute', function (): void {
    $escaped = new Escaper()->url('https://example.com/a?x=1&y=2');

    expect($escaped)->toBe('https://example.com/a?x=1&amp;y=2');
});

it('preserves fragments as client-side fragments', function (): void {
    $escaped = new Escaper()->url('https://example.com/callback?ok=1#access_token=SECRET');

    expect($escaped)->toBe('https://example.com/callback?ok=1#access_token=SECRET');
});

it('normalizes a fragment once when legacy encoding is requested', function (): void {
    $escaped = new Escaper()->url('https://example.com/callback?ok=1#a+b', [], true);

    expect($escaped)->toBe('https://example.com/callback?ok=1#a%2Bb');
});

it('does not decode nested URL query values into the outer URL', function (): void {
    $url = 'https://example.com/?next=https%3A%2F%2Fother.test%2Fa%3Fx%3D1%26y%3D2';

    expect(new Escaper()->url($url))->toBe($url);
});

it('uses the caller supplied scheme list as a restriction', function (): void {
    $escaper = new Escaper();

    expect($escaper->url('http://example.com', ['https']))->toBe('')
        ->and($escaper->url('https://example.com', ['https']))->toBe('https://example.com');
});

it('matches allowed schemes case insensitively', function (): void {
    $escaped = new Escaper()->url('HTTPS://example.com/path', ['https']);

    expect($escaped)->toBe('HTTPS://example.com/path');
});

it('retains explicitly allowed non-active schemes for compatibility', function (): void {
    $escaped = new Escaper()->url('ftp://example.com/file', ['ftp']);

    expect($escaped)->toBe('ftp://example.com/file');
});

it('rejects active and local schemes even when supplied by a caller', function (string $url, string $scheme): void {
    expect(new Escaper()->url($url, [$scheme]))->toBe('');
})->with([
    ['javascript://example.com/alert(1)', 'javascript'],
    ['data://text/plain/payload', 'data'],
    ['file://localhost/etc/passwd', 'file'],
]);

it('rejects URLs containing misleading credentials', function (): void {
    $escaped = new Escaper()->url('https://trusted.example:password@evil.example/path');

    expect($escaped)->toBe('');
});

it('uses a consistent empty-string failure result', function (string $url): void {
    expect(new Escaper()->url($url))->toBe('');
})->with([
    '',
    'not a url',
    '//example.com/path',
    'mailto:user@example.com',
]);

it('keeps existing handler code compatible while double encoding entities', function (): void {
    $escaper = new Escaper();

    expect($escaper->js('alert("ok");'))->toBe('alert(&quot;ok&quot;);')
        ->and($escaper->js('&#39;);alert(document.domain);//'))
        ->toBe('&amp;#39;);alert(document.domain);//');
});

it('serializes untrusted JavaScript values without executable HTML delimiters', function (): void {
    $value = '</script><script>alert(\'x\')</script>&"';
    $encoded = new Escaper()->jsValue($value);

    expect($encoded)
        ->not->toContain('</script>')
        ->not->toContain('<')
        ->not->toContain('>')
        ->not->toContain('&')
        ->and(json_decode($encoded, true, flags: JSON_THROW_ON_ERROR))->toBe($value);
});

it('safely transports a handler built with a serialized JavaScript value', function (): void {
    $escaper = new Escaper();
    $value = '&#39;);alert(document.domain);//';
    $handler = 'show(' . $escaper->jsValue($value) . ')';
    $escapedHandler = $escaper->js($handler);
    $browserHandler = html_entity_decode($escapedHandler, ENT_QUOTES | ENT_HTML5, 'UTF-8');

    expect($browserHandler)->toBe($handler)
        ->and($browserHandler)->not->toContain("show('');alert");
});
