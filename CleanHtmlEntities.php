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

interface CleanHtmlEntities
{
    /**
     * Escaping for HTML blocks.
     *
     * @return string Escaped HTML block.
     */
    public function html(string $string): string;

    /**
     * Escaping for textarea.
     *
     * @return string Escaped string.
     */
    public function textarea(string $string): string;

    /**
     * Escaping for url.
     *
     * @param string $url    The url to be escaped.
     * @param array  $scheme The url scheme.
     * @param bool   $encode Whether the fragment should be normalized with RFC 3986 encoding. This parameter is
     *                       retained for backwards compatibility.
     * @return string A validated URL escaped for use in a quoted HTML attribute, or an empty string when invalid.
     *
     * This method does not enforce a trusted host, redirect policy, or public network destination.
     */
    public function url(string $url, array $scheme = [], bool $encode = false): string;

    /**
     * Escaping for HTML attributes.
     *
     * The returned value is only safe inside a quoted, ordinary HTML attribute. URL, CSS, JavaScript, and srcdoc
     * attributes require their own context-specific validation or encoding.
     *
     * @return string Escaped HTML attribute.
     */
    public function attr(string $string): string;

    /**
     * Escaping fully constructed inline JavaScript for a quoted HTML attribute.
     *
     * This method does not make untrusted JavaScript code safe. Values must be safely serialized before they are
     * interpolated into JavaScript code.
     *
     * @return string Escaped inline javascript.
     */
    public function js(string $string): string;
}
