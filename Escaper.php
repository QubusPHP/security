<?php

/**
 * Qubus\Security
 *
 * @link       https://github.com/QubusPHP/security
 * @copyright  2020
 * @author     Joshua Parker <joshua@joshuaparker.dev>
 * @license    https://opensource.org/licenses/mit-license.php MIT License
 */

declare(strict_types=1);

namespace Qubus\Security;

use Qubus\EventDispatcher\ActionFilter\Observer;
use Qubus\Exception\Exception;

use function array_key_exists;
use function htmlspecialchars;
use function filter_var;
use function is_array;
use function is_string;
use function in_array;
use function json_encode;
use function mb_convert_encoding;
use function parse_url;
use function rawurldecode;
use function rawurlencode;
use function strlen;
use function strtolower;
use function strpos;
use function substr;

use const FILTER_VALIDATE_URL;
use const ENT_HTML5;
use const ENT_QUOTES;
use const ENT_SUBSTITUTE;
use const JSON_HEX_AMP;
use const JSON_HEX_APOS;
use const JSON_HEX_QUOT;
use const JSON_HEX_TAG;
use const JSON_THROW_ON_ERROR;

class Escaper implements CleanHtmlEntities
{
    private const array DEFAULT_URL_SCHEMES = ['http', 'https'];

    /**
     * Schemes that must never be emitted into an active browser context.
     */
    private const array UNSAFE_URL_SCHEMES = ['blob', 'data', 'file', 'javascript', 'vbscript'];

    private const int HTML_FLAGS = ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5;

    /**
     * Convert special characters to HTML entities
     *
     * @param string $string         The string being converted.
     * @param int    $flags          A bitmask of one or more flags.
     * @param string $encoding       An optional argument defining the encoding used when converting characters.
     * @param bool   $doubleEncoding When double_encode is turned off PHP will not encode existing html entities,
     *                               the default is to convert everything.
     * @throws Exception
     */
    private function htmlSpecialChars(
        string $string,
        int $flags = self::HTML_FLAGS,
        string $encoding = 'UTF-8',
        bool $doubleEncoding = false,
        bool $forceDoubleEncoding = false
    ): string {
        if (0 === strlen($string)) {
            return '';
        }

        /**
         * Filter the character encoding.
         *
         * @param string $encoding Default: UTF-8.
         */
        $filteredEncoding = new Observer()->filter->applyFilter('escaper_character_encoding', $encoding);

        // Public escaping methods normalize their input to UTF-8. Interpreting those
        // bytes as another character set can cause data loss or inconsistent output.
        $utf8Aliases = ['utf8' => 'UTF-8', 'utf-8' => 'UTF-8', 'UTF8' => 'UTF-8', 'UTF-8' => 'UTF-8'];
        $encoding = is_string($filteredEncoding) ? ($utf8Aliases[$filteredEncoding] ?? 'UTF-8') : 'UTF-8';

        /**
         * Filter double encoding.
         *
         * @param bool $doubleEncoding Default: false.
         */
        $filteredDoubleEncoding = new Observer()->filter->applyFilter(
            'escaper_double_encoding',
            $doubleEncoding
        );
        $doubleEncoding = $forceDoubleEncoding ? true : (bool) $filteredDoubleEncoding;

        return htmlspecialchars($string, $flags, $encoding, $doubleEncoding);
    }

    /**
     * Escaping for HTML blocks.
     *
     * @return string Escaped HTML block.
     * @throws Exception
     */
    public function html(string $string): string
    {
        $utf8String = mb_convert_encoding($string, 'UTF-8', 'UTF-8');
        return $this->htmlSpecialChars($utf8String, self::HTML_FLAGS);
    }

    /**
     * Escaping for textarea.
     *
     * @return string Escaped string.
     * @throws Exception
     */
    public function textarea(string $string): string
    {
        $utf8String = mb_convert_encoding($string, 'UTF-8', 'UTF-8');
        return $this->htmlSpecialChars($utf8String, self::HTML_FLAGS);
    }

    /**
     * Escaping for url. This method does not enforce a trusted host,
     * redirect policy, or public network destination.
     *
     * @param string $url   The url to be escaped.
     * @param array $scheme The url scheme.
     * @param bool $encode  Whether the fragment should be normalized with RFC 3986 encoding. This parameter is
     *                      retained for backwards compatibility.
     * @return string A validated URL escaped for use in a quoted HTML attribute, or an empty string when invalid.
     * @throws Exception
     */
    public function url(string $url, array $scheme = [], bool $encode = false): string
    {
        if ('' === $url) {
            return '';
        }

        $validatedUrl = filter_var($url, FILTER_VALIDATE_URL);
        if (! is_string($validatedUrl)) {
            return '';
        }

        $uri = parse_url($validatedUrl);

        if (! is_array($uri)) {
            return '';
        }

        $urlScheme = strtolower($uri['scheme'] ?? '');
        $allowedSchemes = [] === $scheme ? self::DEFAULT_URL_SCHEMES : $scheme;
        $schemeIsAllowed = false;

        foreach ($allowedSchemes as $allowedScheme) {
            if (is_string($allowedScheme) && $urlScheme === strtolower($allowedScheme)) {
                $schemeIsAllowed = true;
                break;
            }
        }

        if (
            ! $schemeIsAllowed
            || in_array($urlScheme, self::UNSAFE_URL_SCHEMES, true)
            || isset($uri['user'])
            || isset($uri['pass'])
        ) {
            return '';
        }

        if ($encode && array_key_exists('fragment', $uri)) {
            $fragmentPosition = strpos($validatedUrl, '#');
            if (false !== $fragmentPosition) {
                $validatedUrl = substr($validatedUrl, 0, $fragmentPosition) . '#'
                . rawurlencode(rawurldecode($uri['fragment']));
            }
        }

        return $this->htmlSpecialChars(
            $validatedUrl,
            self::HTML_FLAGS,
            'UTF-8',
            true,
            true
        );
    }

    /**
     * Escaping for HTML attributes.
     *
     * The returned value is only safe inside a quoted, ordinary HTML attribute. URL, CSS, JavaScript, and srcdoc
     * attributes require their own context-specific validation or encoding.
     *
     * @return string Escaped HTML attribute.
     * @throws Exception
     */
    public function attr(string $string): string
    {
        $utf8String = mb_convert_encoding($string, 'UTF-8', 'UTF-8');
        return $this->htmlSpecialChars($utf8String, self::HTML_FLAGS);
    }

    /**
     * Escaping fully constructed inline JavaScript for a quoted HTML attribute.
     *
     * This method does not make untrusted JavaScript code safe. Untrusted values must first be serialized with
     * jsValue(), or preferably passed through data attributes to an external event listener.
     *
     * Example usage:
     *
     *      $esc_js = json_encode("Joshua's \"code\"");
     *      $attribute = $this->js("alert($esc_js);");
     *      echo '<input type="button" value="push" onclick="'.$attribute.'" />';
     *
     * @return string Escaped inline javascript.
     * @throws Exception
     */
    public function js(string $string): string
    {
        $utf8String = mb_convert_encoding($string, 'UTF-8', 'UTF-8');

        // Existing entities must be encoded here because browsers decode an event
        // attribute before compiling it as JavaScript.
        return $this->htmlSpecialChars(
            $utf8String,
            self::HTML_FLAGS,
            'UTF-8',
            true,
            true
        );
    }

    /**
     * Serialize an untrusted value as a JavaScript expression.
     *
     * The returned expression is safe to embed in an HTML script block. When it is used to build an inline event
     * handler, pass the fully constructed handler through js() before inserting it into a quoted attribute.
     *
     * @throws \JsonException
     */
    public function jsValue(mixed $value): string
    {
        return json_encode(
            $value,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR
        );
    }
}
