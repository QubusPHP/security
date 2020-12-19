<?php

/**
 * Qubus\Security
 *
 * @link       https://github.com/QubusPHP/security
 * @copyright  2020 Joshua Parker
 * @license    https://opensource.org/licenses/mit-license.php MIT License
 *
 * @since      1.0.0
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
     * @param bool   $encode Whether url params should be encoded.
     * @return string The escaped $url after the `esc_url` filter is applied.
     */
    public function url(string $url, array $scheme = [], bool $encode = false): string;

    /**
     * Escaping for HTML attributes.
     *
     * @return string Escaped HTML attribute.
     */
    public function attr(string $string): string;

    /**
     * Escaping for inline javascript.
     *
     * @return string Escaped inline javascript.
     */
    public function js(string $string): string;
}
