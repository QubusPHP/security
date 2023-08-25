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

interface Purifier
{
    /**
     * Escaping for rich text.
     *
     * This method should only be used on output. With the exception of uploading
     * images, never use this method on input. All inputted data should be
     * accepted and then purified on output for optimal results.
     *
     * @param string $string The string to purify.
     * @param bool $isImage Is the string an image?
     * @return string|bool|array Escaped rich text.
     */
    public function purify(string $string, bool $isImage = false): string|bool|array;
}
