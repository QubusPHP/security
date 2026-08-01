<?php

declare(strict_types=1);

use Qubus\Security\HtmlPurifier;

use function Qubus\Security\Helpers\purify_html;

it('returns a purifier instance when the helper receives null', function (): void {
    expect(purify_html())->toBeInstanceOf(HtmlPurifier::class)
        ->and(purify_html(null))->toBeInstanceOf(HtmlPurifier::class);
});

it('keeps the helper compatible with string, array, and image-check input', function (): void {
    expect(purify_html('<p>safe</p>'))->toBe('<p>safe</p>')
        ->and(purify_html(['body' => '<p>safe</p>']))->toBe(['body' => '<p>safe</p>'])
        ->and(purify_html('plain metadata', true))->toBeTrue();
});

it('preserves ordinary rich text and safe attributes', function (): void {
    $html = '<article class="entry"><h2>Title</h2><p>Hello <strong>world</strong>.</p></article>';

    expect(new HtmlPurifier()->purify($html))->toBe($html);
});

it('removes executable and embedded elements using a structural allow list', function (string $html): void {
    $purified = new HtmlPurifier()->purify($html);

    expect($purified)
        ->not->toMatch('/<(?:iframe|math|object|script|style|svg|template)\b/i')
        ->not->toContain('alert(1)');
})->with([
    '<iframe src="https://attacker.example"></iframe>',
    '<svg><script>alert(1)</script></svg>',
    '<math><mtext><style>body{display:none}</style></mtext></math>',
    '<template><img src="x" onerror="alert(1)"></template>',
    '<object data="https://attacker.example/payload"></object>',
]);

it('unwraps unknown formatting elements while retaining safe descendants', function (): void {
    $purified = new HtmlPurifier()->purify('<custom-element><b>safe text</b></custom-element>');

    expect($purified)->toBe('<b>safe text</b>');
});

it('removes event, CSS, namespace, and document-producing attributes', function (): void {
    $html = '<div class="safe" style="background:url(javascript:alert(1))" onclick="alert(1)" '
        . 'xmlns="urn:x" srcdoc="<script>alert(1)</script>">content</div>';
    $purified = new HtmlPurifier()->purify($html);

    expect($purified)->toBe('<div class="safe">content</div>');
});

it('rejects active and local URI schemes in every URI attribute', function (string $html): void {
    $purified = new HtmlPurifier()->purify($html);

    expect($purified)
        ->not->toMatch('/\b(?:href|src|cite)\s*=/i')
        ->not->toMatch('/(?:blob|data|file|javascript|vbscript)\s*:/i');
})->with([
    '<a href="javascript:alert(1)">link</a>',
    '<a href="java&#x09;script:alert(1)">link</a>',
    '<a href="%256a%2561vascript:alert(1)">link</a>',
    '<img src="data:image/svg+xml,<svg onload=alert(1)>">',
    '<img src="blob:https://example.test/id">',
    '<blockquote cite="file:///etc/passwd">quote</blockquote>',
]);

it('retains safe absolute, relative, mail, and telephone links', function (): void {
    $purifier = new HtmlPurifier();

    expect($purifier->purify('<a href="https://example.test/path">web</a>'))
        ->toBe('<a href="https://example.test/path">web</a>')
        ->and($purifier->purify('<a href="/relative/path">relative</a>'))
        ->toBe('<a href="/relative/path">relative</a>')
        ->and($purifier->purify('<a href="mailto:user@example.test">mail</a>'))
        ->toBe('<a href="mailto:user@example.test">mail</a>')
        ->and($purifier->purify('<a href="tel:+15551234567">call</a>'))
        ->toBe('<a href="tel:+15551234567">call</a>');
});

it('prevents reverse-tabnabbing on links opening a new window', function (): void {
    $purified = new HtmlPurifier()->purify(
        '<a href="https://example.test" target="_blank" rel="author">link</a>'
    );

    expect($purified)->toBe(
        '<a href="https://example.test" target="_blank" rel="author noopener noreferrer">link</a>'
    );
});

it('does not let public allow lists opt into active content', function (): void {
    $purifier = new HtmlPurifier();
    $purifier->allowedHtmlElements[] = 'script';
    $purifier->allowedHtmlAttributes[] = 'style';
    $purifier->allowedUriSchemes[] = 'javascript';

    $purified = $purifier->purify(
        '<script>alert(1)</script><a style="color:red" href="javascript:alert(1)">link</a>'
    );

    expect($purified)
        ->toContain('<a>link</a>')
        ->not->toContain('<script')
        ->not->toContain('style=')
        ->not->toContain('href=');
});

it('decodes semicolonless numeric and HTML5 named entities correctly', function (): void {
    $purifier = new HtmlPurifier();

    expect($purifier->entityDecode('&#65'))->toBe('A')
        ->and($purifier->entityDecode('&#x41'))->toBe('A')
        ->and($purifier->entityDecode('&#x1F642'))->toBe('🙂')
        ->and($purifier->entityDecode('&apos;'))->toBe("'");
});

it('keeps array input compatible and propagates image-check mode', function (): void {
    $purifier = new HtmlPurifier();

    expect($purifier->purify(['safe' => '<p>text</p>']))->toBe(['safe' => '<p>text</p>'])
        ->and($purifier->purify(['safe' => 'plain text', 'unsafe' => '<?php echo 1; ?>'], true))
        ->toBe(['safe' => true, 'unsafe' => false]);
});

it('sanitizes cross-platform and encoded filename traversal', function (string $filename): void {
    expect(new HtmlPurifier()->sanitizeFilename($filename))->toBe('secret.php');
})->with([
    '../../secret.php',
    '..\\..\\secret.php',
    '%2E%2E%2Fsecret.php',
]);

it('removes filename control characters and preserves approved relative paths', function (): void {
    $purifier = new HtmlPurifier();

    expect($purifier->sanitizeFilename("report\r\n.php"))->toBe('report.php')
        ->and($purifier->sanitizeFilename('approved/path/file.txt', true))
        ->toBe('approved/path/file.txt')
        ->and($purifier->sanitizeFilename('../approved/../../file.txt', true))
        ->toBe('approved/file.txt')
        ->and($purifier->sanitizeFilename('/absolute/path/file.txt', true))
        ->toBe('absolute/path/file.txt');
});

it('neutralizes mixed and multiply encoded filename separators', function (string $filename): void {
    $sanitized = new HtmlPurifier()->sanitizeFilename($filename, true);

    expect(rawurldecode(rawurldecode($sanitized)))
        ->not->toContain('../')
        ->not->toContain('..\\');
})->with([
    '..%2Fsecret.php',
    '%2e%2e/secret.php',
    '%252e%252e%252fsecret.php',
]);
