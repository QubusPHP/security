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

namespace Qubus\Security\Helpers;

use Gettext\Translations;
use Gettext\Translator;
use Gettext\TranslatorInterface;

use function d__;
use function is_readable;

/**
 * Returns the Translator object.
 *
 * @access private
 * @return Translator;
 */
function __translator(): TranslatorInterface
{
    return new Translator();
}

/**
 * Displays the returned translated text.
 *
 * @param string $msgid  The translated string.
 * @param string $domain Domain lookup for translated text.
 * @return string Translated text according to current locale.
 */
function t__(string $msgid, string $domain = ''): string
{
    __translator()->register();

    $domain = '' !== $domain ? $domain : 'qubus';

    return d__($domain, $msgid);
}

/**
 * Load default translated strings based on locale.
 *
 * @param string $domain Text domain. Unique ID for retrieving translated strings.
 * @param string $path Path to the .mo file.
 * @return bool True on success, false on failure.
 */
function load_default_textdomain(string $domain, string $path): bool
{
    $locale = load_core_locale();

    $mopath = $path . $domain . '-' . $locale . '.mo';

    return load_textdomain($domain, $mopath);
}

/**
 * Load a .mo file into the text domain.
 *
 * @param string $domain Text domain. Unique ID for retrieving translated strings.
 * @param string $path Path to the .mo file.
 * @return bool True on success, false on failure.
 */
function load_textdomain(string $domain, string $path): bool
{
    /**
     * Filter text domain and/or .mo file path for loading translations.
     *
     * @param bool   $override Should we override textdomain?. Default is false.
     * @param string $domain   Text domain. Unique ID for retrieving translated strings.
     * @param string $path     Path to the .mo file.
     */
    $override = __observer()->filter->applyFilter('override_load_textdomain', false, $domain, $path);

    if (true === $override) {
        return true;
    }

    /**
     * Fires before the .mo translation file is loaded.
     *
     * @param string $domain Text domain. Unique ID for retrieving translated strings.
     * @param string $path Path to the .mo file.
     */
    __observer()->action->doAction('load_textdomain', $domain, $path);

    /**
     * Filter .mo file path for loading translations for a specific text domain.
     *
     * @param string $path Path to the .mo file.
     * @param string $domain Text domain. Unique ID for retrieving translated strings.
     */
    $mofile = __observer()->filter->applyFilter('load_textdomain_mofile', $path, $domain);
    // Load only if the .mo file is present and readable.
    if (! is_readable($mofile)) {
        return false;
    }

    $translations = Translations::fromMoFile($mofile);
    __translator()->loadTranslations($translations);

    return true;
}

/**
 * Loads the current or default locale.
 *
 * @return string The locale.
 */
function load_core_locale(): string
{
    $locale = 'en';

    return __observer()->filter->applyFilter('core_locale', $locale);
}
