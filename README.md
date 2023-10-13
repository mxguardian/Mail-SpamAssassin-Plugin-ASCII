# NAME

Mail::SpamAssassin::Plugin::ASCII - SpamAssassin plugin to convert non-ASCII characters to their ASCII equivalents

# SYNOPSIS

    loadplugin Mail::SpamAssassin::Plugin::ASCII

    ascii      RULE_NAME   /You have a new voice-?mail/i
    describe   RULE_NAME   Voice mail spam
    score      RULE_NAME   1.0

# DESCRIPTION

This plugin defines a new rule type called `ascii` that is used to match
against an ASCII-only version of the message body. When a message is scanned,
this plugin makes a copy of the message body, converts it to ASCII characters
and then runs rules against the converted text. This is useful for
catching spam that uses non-ASCII characters to obfuscate words. For example,
a message containing the text

    Ýou hãve a nèw vòice-mãil

would be converted to

    You have a new voice-mail

before processing the rules. The actual conversion is done by the Text::ASCII::Convert module.
See [Text::ASCII::Convert](https://metacpan.org/pod/Text%3A%3AASCII%3A%3AConvert) for details.

# REQUIREMENTS

- SpamAssassin 3.4.0 or later
- Text::ASCII::Convert

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
