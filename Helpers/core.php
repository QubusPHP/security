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

use Qubus\EventDispatcher\ActionFilter\Observer;
use Qubus\Security\Escaper;
use Qubus\Security\HtmlPurifier;

use function array_map;
use function array_merge;
use function array_unique;
use function count;
use function current;
use function explode;
use function func_get_args;
use function implode;
use function is_array;
use function key;
use function next;
use function preg_match_all;
use function preg_replace;
use function stripslashes;

/**
 * Escaper function calling the Escaper class.
 *
 * @access private
 */
function __escaper(): Escaper
{
    return new Escaper();
}

/**
 * Observer function calling the Observer class.
 *
 * @access private
 */
function __observer(): Observer
{
    return new Observer();
}

/**
 * Escaping for HTML output.
 *
 * @param string $string Html element to escape.
 * @return string Escaped HTML output.
 */
function esc_html(string $string): string
{
    $safeString = __escaper()->html($string);
    /**
     * Filters a clean and escaped string for HTML output.
     *
     * @param string $safeString String after it has been escaped.
     * @param string $string     String before it has been escaped.
     */
    return __observer()->filter->applyFilter('esc_html', $safeString, $string);
}

/**
 * Escapes a translated string to make it safe for HTML output.
 *
 * @param string $string String to translate.
 * @param string $domain Optional. Text domain. Default: 'qubus'.
 * @return string Translated string.
 */
function esc_html__(string $string, string $domain = 'qubus'): string
{
    return esc_html(t__($string, $domain));
}

/**
 * Escaping for textarea.
 *
 * @return string Escaped string.
 */
function esc_textarea(string $string): string
{
    $safeString = __escaper()->textarea($string);
    /**
     * Filters a clean and escaped string for textarea output.
     *
     * @param string $safeString String after it has been escaped.
     * @param string $string     String before it has been escaped.
     */
    return __observer()->filter->applyFilter('esc_textarea', $safeString, $string);
}

/**
 * Escaping for url.
 *
 * @param string $url    The url to be escaped.
 * @param array  $scheme Optional. An array of acceptable schemes.
 * @param bool   $encode Whether url params should be encoded.
 * @return string The escaped $url after the `esc_url` filter is applied.
 */
function esc_url(string $url, array $scheme = ['http', 'https'], bool $encode = false): string
{
    $safeUrl = __escaper()->url($url, $scheme, $encode);
    /**
     * Filters a clean and escaped url for output.
     *
     * @param string $safeUrl The escaped url to be returned.
     * @param string $url     The url prior to being escaped.
     */
    return __observer()->filter->applyFilter('esc_url', $safeUrl, $url);
}

/**
 * Escaping for HTML attributes.
 *
 * @return string Escaped HTML attribute.
 */
function esc_attr(string $string): string
{
    $safeString = __escaper()->attr($string);
    /**
     * Filters a clean and escaped string for HTML attribute output.
     *
     * @param string $safeString String after it has been escaped.
     * @param string $string     String before it has been escaped.
     */
    return __observer()->filter->applyFilter('esc_attr', $safeString, $string);
}

/**
 * Escapes a translated string to make it safe for HTML attribute.
 *
 * @param string $string String to translate.
 * @param string $domain Optional. Unique identifier for retrieving translated string.
 *                       Default: 'qubus'.
 * @return string Translated string.
 */
function esc_attr__(string $string, string $domain = 'qubus'): string
{
    return esc_attr(t__($string, $domain));
}

/**
 * Escaping for inline javascript.
 *
 * Example usage:
 *
 *      $esc_js = json_encode("Joshua's \"code\"");
 *      $attribute = esc_js("alert($esc_js);");
 *      echo '<input type="button" value="push" onclick="'.$attribute.'" />';
 *
 * @return string Escaped inline javascript.
 */
function esc_js(string $string): string
{
    $safeString = __escaper()->js($string);
    /**
     * Filters a clean and escaped string for inline javascript output.
     *
     * @param string $safeString String after it has been escaped.
     * @param string $string     String before it has been escaped.
     */
    return __observer()->filter->applyFilter('esc_js', $safeString, $string);
}

/**
 * Makes content safe to print on screen.
 *
 * This function should only be used on output. With the exception of uploading
 * images, never use this function on input. All inputted data should be
 * accepted and then purified on output for optimal results. For output of images,
 * make sure to escape with esc_url().
 *
 * @param string $string Text to purify.
 */
function purify_html(string $string, bool $isImage = false): string
{
    return (
    new HtmlPurifier()
    )->purify($string, $isImage);
}

/**
 * Split a delimited string into an array.
 *
 * @param array|string $delimiters Delimiter(s) to search for.
 * @param array|string $string     String or array to be split.
 * @return array Return array.
 */
function explode_array(array|string $delimiters, array|string $string): array
{
    if (! is_array($delimiters) && ! is_array($string)) {
        //if neither the delimiter nor the string are arrays
        return explode($delimiters, $string);
    } elseif (! is_array($delimiters) && is_array($string)) {
        //if the delimiter is not an array but the string is
        foreach ($string as $item) {
            foreach (explode($delimiters, $item) as $subItem) {
                $items[] = $subItem;
            }
        }
        return $items;
    } elseif (is_array($delimiters) && ! is_array($string)) {
        //if the delimiter is an array but the string is not
        $stringArray[] = $string;
        foreach ($delimiters as $delimiter) {
            $stringArray = explode_array($delimiter, $stringArray);
        }
        return $stringArray;
    }
}

/**
 * Replaces the deprecated PHP `each` function.
 *
 * Return the current key and value pair from an array and advance the array cursor.
 *
 * @param array $arr The input array.
 * @return array|false Returns the current key and value pair from the array.
 */
function each__(array &$arr): array|false
{
    $key = key($arr);
    $result = $key === null ? false : [$key, current($arr), 'key' => $key, 'value' => current($arr)];
    next($arr);
    return $result;
}

/**
 * Navigates through an array, object, or scalar, and removes slashes from the values.
 *
 * @param mixed $value  The value to be stripped.
 * @return array|string Stripped value.
 */
function stripslashes_deep(mixed $value): array|string
{
    return is_array($value) ?
    array_map([__FUNCTION__, 'stripslashes_deep'], $value) :
    stripslashes($value);
}

/**
 * This should be used to remove slashes from data passed to core API that
 * expects data to be unslashed.
 *
 * @param string|array $value String or array of strings to unslash.
 * @return string|array Unslashed value.
 */
function unslash(mixed $value): array|string
{
    return stripslashes_deep($value);
}

/**
 * Turns multi-dimensional array into a regular array.
 *
 * @param array $array The array to flatten.
 * @return array
 */
function flatten_array(array $array): array
{
    $flatArray = [];

    if (! is_array($array)) {
        $array = func_get_args();
    }

    foreach ($array as $key => $value) {
        if (is_array($value)) {
            $flatArray = array_merge($flatArray, flatten_array($value));
        } else {
            $flatArray = array_merge($flatArray, [$key => $value]);
        }
    }
    return $flatArray;
}

/**
 * Removes all whitespace.
 *
 * @param array|string $string $string String to trim.
 * @return array|string|null
 */
function trim__(array|string $string): array|string|null
{
    return preg_replace('/\s/', '', $string);
}

/**
 * Properly strip all HTML tags including script and style (default).
 *
 * This differs from PHP's native `strip_tags()` function because this function removes the contents of
 * the tags. E.g. `strip_tags__( '<script>something</script>' )`
 * will return `''`.
 *
 * Example Usage:
 *
 *      $string = '<b>sample</b> text with <div>tags</div>';
 *
 *      strip_tags__($string); //returns 'text with'
 *      strip_tags__($string, false, '<b>'); //returns '<b>sample</b> text with'
 *      strip_tags__($string, false, '<b>', true); //returns 'text with <div>tags</div>'
 *
 * @param string $string       String containing HTML tags.
 * @param bool   $removeBreaks Optional. Whether to remove left over line breaks and white space chars.
 * @param string $tags         Tags that should be removed.
 * @param bool   $invert       Instead of removing tags, this option checks for which tags to not remove.
 *                             Default: false.
 * @return string The processed string.
 */
function strip_tags__(
    string $string,
    bool $removeBreaks = false,
    string $tags = '',
    bool $invert = false
): string {
    $rawString = $string;

    $newString = preg_replace('@<(script|style)[^>]*?>.*?</\\1>@si', '', $string);

    preg_match_all('/<(.+?)[\s]*\/?[\s]*>/si', trim__($tags), $tags);
    $newTags = array_unique($tags[1]);

    if (is_array($newTags) && count($newTags) > 0) {
        if ($invert === false) {
            return preg_replace('@<(?!(?:' . implode('|', $newTags) . ')\b)(\w+)\b.*?>.*?</\1>@si', '', $newString);
        } else {
            return preg_replace('@<(' . implode('|', $newTags) . ')\b.*?>.*?</\1>@si', '', $newString);
        }
    } elseif ($invert === false) {
        return preg_replace('@<(\w+)\b.*?>.*?</\1>@si', '', $newString);
    }

    if ($removeBreaks) {
        $newString = preg_replace('/[\r\n\t ]+/', ' ', $newString);
    }

    return __observer()->filter->applyFilter(
        'strip_tags',
        $newString,
        $rawString,
        $removeBreaks,
        $tags,
        $invert
    );
}

/**
 * PHP die's function wrapped in pretty css.
 *
 * @param string $message Message to be returned.
 */
function die__(string $message): void
{
    die(
        "<link rel=\"stylesheet\" href=\"style.css\">\n<div class=\"die-alert die-alert-info\">$message</div>\n"
    );
}
