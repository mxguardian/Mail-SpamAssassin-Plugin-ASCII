# NAME

Mail::SpamAssassin::Plugin::ASCII - SpamAssassin plugin to convert non-ASCII characters to their ASCII equivalents

# SYNOPSIS

    loadplugin Mail::SpamAssassin::Plugin::ASCII

    ascii      RULE_NAME   /You have a new voice-?mail/i
    describe   RULE_NAME   Voice mail spam
    score      RULE_NAME   1.0

# DESCRIPTION

This plugin makes a copy of the message body, converts it to ASCII characters
and then runs rules against the converted text. This is useful for
catching spam that uses non-ASCII characters to obfuscate words. For example,
a message containing the text

    Ýou hãve a nèw vòice-mãil

would be converted to

    You have a new voice-mail

# RULE DEFINITION

To define a rule that matches against the ASCII version of the message body,
use the `ascii` rule type. The rule definition is similar to a `body` rule
definition, but the pattern is a regular expression that matches the ASCII
version of the text.

## RULE DEFINITION EXAMPLE

    ascii      RULE_NAME   /voice\W?mail/i
    describe   RULE_NAME   Message contains the word "voice mail"
    score      RULE_NAME   0.001

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

# EVAL RULES

- ascii\_unicode\_obfuscation

    This rule evaluates to true if the message body contains any words from a pre-defined list that are
    obfuscated by using non-ASCII characters. The rule takes an optional argument that specifies the maximum
    number of words to check. If the optional argument is not provided, all words in the message body are checked.

    Example:

        body ASCII_OBFUSCATION eval:ascii_unicode_obfuscation(100)
        score ASCII_OBFUSCATION 1.0
        describe ASCII_OBFUSCATION Obfuscated word found

# CONFIGURATION

- ascii\_obfuscation\_words

    This option specifies a list of words that are considered obfuscated if they contain non-ASCII characters.
    The words are case-insensitive. Multiple words can be specified on the same line, separated by whitespace.
    This option can be used multiple times to add more words to the list.

    Example:

        ascii_obfuscation_words   norton mcafee symantec
        ascii_obfuscation_words   microsoft apple google
        ascii_obfuscation_words   dropbox docusign adobe

# REQUIREMENTS

- SpamAssassin 3.4.0 or later
- Text::ASCII::Convert

# AUTHORS

Kent Oyer <kent@mxguardian.net>

# COPYRIGHT AND LICENSE

Copyright (C) 2023 MXGuardian LLC

This is free software; you can redistribute it and/or modify it under
the terms of the Apache License 2.0. See the LICENSE file included
with this distribution for more information.

This plugin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
