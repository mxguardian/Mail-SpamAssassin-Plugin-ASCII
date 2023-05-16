# NAME

Mail::SpamAssassin::Plugin::ASCII - SpamAssassin plugin to convert non-ASCII characters to their ASCII equivalents

# SYNOPSIS

    loadplugin Mail::SpamAssassin::Plugin::ASCII

    ascii      RULE_NAME   /You have a new voice-?mail/i
    describe   RULE_NAME   Voice mail spam
    score      RULE_NAME   1.0

# DESCRIPTION

This plugin attempts to convert non-ASCII characters to their ASCII equivalents
and then run rules against the converted text.  This is useful for
catching spam that uses non-ASCII characters to obfuscate words. For example,

    Ýou hãve a nèw vòice-mãil
    PαyPal
    You havé Reꞓeìved an Enꞓryptéd Company Maíl
    ѡѡѡ.ЬіɡЬаɡ.ϲо.zа

would be converted to

    You have a new voice-mail
    PayPal
    You have ReCeived an EnCrypted Company Mail
    www.bigbag.co.za

Unlike other transliteration software, this plugin converts non-ASCII characters
to their ASCII equivalents based on appearance instead of meaning. For example, the
German eszett character 'ß' is converted to the Roman letter 'B' instead of 'ss'
because it resembles a 'B' in appearance. Likewise, the Greek letter Sigma ('Σ') is
converted to 'E' and a lower case Omega ('ω') is converted to 'w' even though these
letters have different meanings than their originals.

Not all non-ASCII characters are converted. For example, the Japanese Hiragana
character 'あ' is not converted because it does not resemble any ASCII character.
Characters that have no ASCII equivalent are removed from the text.

The plugin also removes zero-width characters such as the zero-width
space (U+200B) and zero-width non-joiner (U+200C) that are often used to
obfuscate words.

If you want to write rules that match against the original non-ASCII text,
you can still do so by using the standard `body` and `rawbody` rules. The
converted text is only used when evaluating rules that use the `ascii` rule type.

Note that obfuscation is still possible within the ASCII character set. For example,
the letter 'O' can be replaced with the number '0' and the letter 'l' can be replaced
with the number '1' as in "PayPa1 0rder". This plugin does not attempt to catch these
types of obfuscation. Therefore, you still need to use other techniques such as using
a character class or `replace_tags` to catch these types of obfuscation.

# TFLAGS

This plugin supports the following `tflags`:

- nosubject

    By default the message Subject header is considered part of the body and becomes the first line
    when running the rules. If you don't want to match Subject along with body text, use "tflags RULENAME nosubject"

- multiple

    The test will be evaluated multiple times, for use with meta rules.

- maxhits=N

    If multiple is specified, limit the number of hits found to N. If the rule is used in a meta rule that counts
    the hits (e.g. \_\_RULENAME > 5), this is a way to avoid wasted extra work (use "tflags \_\_RULENAME multiple maxhits=6").

# AUTHORS

Kent Oyer <kent@mxguardian.net>

# COPYRIGHT AND LICENSE

Copyright (C) 2023 MXGuardian LLC

This is free software; you can redistribute it and/or modify it under
the terms of the Apache License 2.0. See the LICENSE file included
with this distribution for more information.

This plugin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
