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

use function urlencode;
use function urldecode;
use function strlen;
use function strip_tags;
use function parse_url;
use function mb_convert_encoding;
use function is_array;
use function in_array;
use function htmlspecialchars;
use function filter_var;

use const FILTER_VALIDATE_URL;
use const FILTER_SANITIZE_SPECIAL_CHARS;
use const ENT_QUOTES;
use const ENT_HTML5;

class Escaper implements CleanHtmlEntities
{
    /**
     * Convert special characters to HTML entities
     *
     * @param string $string         The string being converted.
     * @param int    $flags          A bitmask of one or more flags.
     * @param string $encoding       An optional argument defining the encoding used when converting characters.
     * @param bool   $doubleEncoding When double_encode is turned off PHP will not encode existing html entities,
     *                               the default is to convert everything.
     */
    private function htmlSpecialChars(
        string $string,
        int $flags = ENT_QUOTES | ENT_HTML5,
        string $encoding = 'UTF-8',
        bool $doubleEncoding = true
    ): string {
        if (0 === strlen($string)) {
            return '';
        }

        if (in_array($encoding, ['utf8', 'utf-8', 'UTF8', 'UTF-8'])) {
            $encoding = 'UTF-8';
        }

        /**
         * Filter the character encoding.
         *
         * @param string $encoding Default: UTF-8.
         */
        $encoding = (new Observer())->filter->applyFilter('escaper_character_encoding', $encoding);
        /**
         * Filter double encoding.
         *
         * @param bool $doubleEncoding Default: true.
         */
        $doubleEncoding = (new Observer())->filter->applyFilter('escaper_double_encoding', (bool) $doubleEncoding);

        return htmlspecialchars($string, $flags, $encoding, $doubleEncoding);
    }

    /**
     * Escaping for HTML blocks.
     *
     * @return string Escaped HTML block.
     */
    public function html(string $string): string
    {
        $utf8String = mb_convert_encoding($string, 'UTF-8', 'UTF-8');
        return $this->htmlSpecialChars($utf8String, ENT_QUOTES);
    }

    /**
     * Escaping for textarea.
     *
     * @return string Escaped string.
     */
    public function textarea(string $string): string
    {
        $utf8String = mb_convert_encoding($string, 'UTF-8', 'UTF-8');
        return $this->htmlSpecialChars($utf8String, ENT_QUOTES);
    }

    /**
     * Escaping for url.
     *
     * @param string $url    The url to be escaped.
     * @param array  $scheme The url scheme.
     * @param bool   $encode Whether url params should be encoded.
     * @return string The escaped $url after the `escUrl` filter is applied.
     */
    public function url(string $url, array $scheme = [], bool $encode = false): string
    {
        $rawUrl = $url;

        if ('' === $url) {
            return $url;
        }

        /**
         * First step of defense is to strip all tags.
         */
        $escUrl = strip_tags($url);

        /**
         * Run url through a filter, and then validate it.
         */
        $newUrl = filter_var(urldecode($escUrl), FILTER_SANITIZE_SPECIAL_CHARS);
        if (! filter_var($newUrl, FILTER_VALIDATE_URL)) {
            return '';
        }

        /**
         * Merge default schemes with provided scheme(s).
         */
        $scheme = array_merge($scheme, ['http', 'https']);

        /**
         * Break down the url into it's parts and then rebuild it.
         */
        $uri = parse_url($newUrl);

        if (! is_array($uri)) {
            return '#';
        }

        if (! in_array($uri['scheme'], $scheme, true)) {
            return '#';
        }

        $query = $uri['query'] ?? '';
        $result = '';

        if (isset($uri['scheme'])) {
            $result .= $uri['scheme'] . ':';
        }
        if (isset($uri['host'])) {
            $result .= '//' . $uri['host'];
        }
        if (isset($uri['port'])) {
            $result .= ':' . $uri['port'];
        }
        if (isset($uri['path'])) {
            $result .= $uri['path'];
        }

        $fragment = $uri['fragment'] ?? '';

        $newQuery = $query . $fragment;

        if ($query) {
            $newQuery = '?' . $query . $fragment;
        }

        $cleanUrl = $result . $newQuery;

        if ($encode) {
            $cleanUrl = $result . $newQuery . urlencode($fragment);
        }

        return $cleanUrl;
    }

    /**
     * Escaping for HTML attributes.
     *
     * @return string Escaped HTML attribute.
     */
    public function attr(string $string): string
    {
        $utf8String = mb_convert_encoding($string, 'UTF-8', 'UTF-8');
        return $this->htmlSpecialChars($utf8String, ENT_QUOTES);
    }

    /**
     * Escaping for inline javascript.
     *
     * Example usage:
     *
     *      $esc_js = json_encode("Joshua's \"code\"");
     *      $attribute = $this->js("alert($esc_js);");
     *      echo '<input type="button" value="push" onclick="'.$attribute.'" />';
     *
     * @return string Escaped inline javascript.
     */
    public function js(string $string): string
    {
        return $this->attr($string);
    }
}
