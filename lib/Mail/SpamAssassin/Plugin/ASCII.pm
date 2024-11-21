# <@LICENSE>
# Licensed under the Apache License 2.0. You may not use this file except in
# compliance with the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>
package Mail::SpamAssassin::Plugin::ASCII;
use strict;
use warnings FATAL => 'all';
no warnings 'redefine';
use v5.12;
use utf8;

=encoding utf8

=head1 NAME

Mail::SpamAssassin::Plugin::ASCII - SpamAssassin plugin to convert non-ASCII characters to their ASCII equivalents

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::ASCII

  ascii      RULE_NAME   /You have a new voice-?mail/i
  describe   RULE_NAME   Voice mail spam
  score      RULE_NAME   1.0

=head1 DESCRIPTION

This plugin makes a copy of the message body, converts it to ASCII characters
and then runs rules against the converted text. This is useful for
catching spam that uses non-ASCII characters to obfuscate words. For example,
a message containing the text

    Ýou hãve a nèw vòice-mãil

would be converted to

    You have a new voice-mail

=head1 RULE DEFINITION

To define a rule that matches against the ASCII version of the message body,
use the C<ascii> rule type. The rule definition is similar to a C<body> rule
definition, but the pattern is a regular expression that matches the ASCII
version of the text.

=head2 RULE DEFINITION EXAMPLE

    ascii      RULE_NAME   /voice\W?mail/i
    describe   RULE_NAME   Message contains the word "voice mail"
    score      RULE_NAME   0.001

=head1 TFLAGS

This plugin supports the following C<tflags>:

=over 4

=item nosubject

By default the message Subject header is considered part of the body and becomes the first line
when running the rules. If you don't want to match Subject along with body text, use "tflags RULENAME nosubject"

=item multiple

The test will be evaluated multiple times, for use with meta rules.

=item maxhits=N

If multiple is specified, limit the number of hits found to N. If the rule is used in a meta rule that counts
the hits (e.g. __RULENAME > 5), this is a way to avoid wasted extra work (use "tflags __RULENAME multiple maxhits=6").

=back

=head1 EVAL RULES

=over

=item ascii_unicode_obfuscation

This rule evaluates to true if the message body contains any words from a pre-defined list that are
obfuscated by using non-ASCII characters. The rule takes an optional argument that specifies the maximum
number of words to check. If the optional argument is not provided, all words in the message body are checked.

Example:

    body ASCII_OBFUSCATION eval:ascii_unicode_obfuscation(100)
    score ASCII_OBFUSCATION 1.0
    describe ASCII_OBFUSCATION Obfuscated word found

=back

=head1 CONFIGURATION

=over

=item ascii_obfuscation_words

This option specifies a list of words that are considered obfuscated if they contain non-ASCII characters.
The words are case-insensitive. Multiple words can be specified on the same line, separated by whitespace.
This option can be used multiple times to add more words to the list.

Example:

    ascii_obfuscation_words   norton mcafee symantec
    ascii_obfuscation_words   microsoft apple google
    ascii_obfuscation_words   dropbox docusign adobe

=back

=head1 REQUIREMENTS

=over

=item SpamAssassin 3.4.0 or later

=item Text::ASCII::Convert

=back

=head1 AUTHORS

Kent Oyer <kent@mxguardian.net>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2023 MXGuardian LLC

This is free software; you can redistribute it and/or modify it under
the terms of the Apache License 2.0. See the LICENSE file included
with this distribution for more information.

This plugin is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=cut

our $VERSION = 1.2;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger qw(would_log);
use Mail::SpamAssassin::Util qw(compile_regexp &untaint_var);
use Encode;
use Text::ASCII::Convert;
use Unicode::Normalize;

our @ISA = qw(Mail::SpamAssassin::Plugin);

my %dictionary;

# Define a hash for common ligature replacements
my %ligatures = (
    "\x{FB01}" => 'fi',   # LATIN SMALL LIGATURE FI
    "\x{FB02}" => 'fl',   # LATIN SMALL LIGATURE FL
    "\x{00C6}" => 'AE',   # LATIN CAPITAL LETTER AE
    "\x{00E6}" => 'ae',   # LATIN SMALL LETTER AE
    "\x{0152}" => 'OE',   # LATIN CAPITAL LIGATURE OE
    "\x{0153}" => 'oe',   # LATIN SMALL LIGATURE OE
    "\x{0132}" => 'IJ',   # LATIN CAPITAL LIGATURE IJ
    "\x{0133}" => 'ij',   # LATIN SMALL LIGATURE IJ
    "\x{FB00}" => 'ff',   # LATIN SMALL LIGATURE FF
    "\x{FB03}" => 'ffi',  # LATIN SMALL LIGATURE FFI
    "\x{FB04}" => 'ffl',  # LATIN SMALL LIGATURE FFL
);

# Precompile the regex pattern using qr// and join in a single statement
my $ligature_regex = qr/[@{[join '', keys %ligatures]}]/;

# constructor
sub new {
    my $class = shift;
    my $mailsaobject = shift;

    # some boilerplate...
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless ($self, $class);

    $self->set_config($mailsaobject->{conf});

    $self->register_eval_rule("ascii_unicode_obfuscation");

    return $self;
}

sub dbg { Mail::SpamAssassin::Logger::dbg ("ASCII: @_"); }
sub info { Mail::SpamAssassin::Logger::info ("ASCII: @_"); }

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;

    push (@cmds, (
        {
            setting => 'ascii',
            is_priv => 1,
            type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
            code => sub {
                my ($self, $key, $value, $line) = @_;

                if ($value !~ /^(\S+)\s+(.+)$/) {
                    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
                }
                my $name = $1;
                my $pattern = $2;

                my ($re, $err) = compile_regexp($pattern, 1);
                if (!$re) {
                    dbg("Error parsing rule: invalid regexp '$pattern': $err");
                    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
                }

                $conf->{parser}->{conf}->{ascii_rules}->{$name} = $re;

                # just define the test so that scores and lint works
                $self->{parser}->add_test($name, undef,
                    $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);


            }
        },{
            setting => 'ascii_obfuscation_words',
            is_priv => 1,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
            code    => sub {
                my ($self, $key, $value, $line) = @_;
                my @words = split(/\s+/, $value);
                foreach my $word (@words) {
                    $dictionary{lc $word} = 1;
                }
            }
        }
    ));

    $conf->{parser}->register_commands(\@cmds);
}

sub finish_parsing_end {
    my ($self, $opts) = @_;
    my $conf = $opts->{conf};

    # only compile rules if we have any
    return unless exists $conf->{ascii_rules};

    # check if we should include calls to dbg()
    my $would_log = would_log('dbg');

    # build eval string
    my $eval = <<'EOF';
package Mail::SpamAssassin::Plugin::ASCII;

sub _run_ascii_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};
    my ($test_qr,$hits,$nosubj);

    # get ascii body
    my $ascii_body = $self->_get_ascii_body($pms);

    # check all script rules
EOF
    my $loopid = 0;
    foreach my $name (keys %{$conf->{ascii_rules}}) {
        $loopid++;
        my $test_qr = $conf->{ascii_rules}->{$name};
        my $tflags = $conf->{tflags}->{$name} || '';
        my $score = $conf->{scores}->{$name} || 1;

        my $dbg_running_rule = '';
        my $dbg_ran_rule = '';
        if ( $would_log ) {
            $dbg_running_rule = qq(dbg("running rule $name"););
            $dbg_ran_rule = qq(dbg(qq(ran rule $name ======> got hit "\$match")););
        }

        my $ifwhile = 'if';
        my $last = 'last;';
        my $modifiers = 'p';
        my $init_hits = '';

        if ( $tflags =~ /\bmultiple\b/ ) {
            $ifwhile = 'while';
            $modifiers .= 'g';
            if ($tflags =~ /\bmaxhits=(\d+)\b/) {
                $init_hits = "\$hits = 0;";
                $last = "last rule_$loopid if ++\$hits >= $1;";
            } else {
                $last = '';
            }
        }

        my $init_subject = '';
        my $skip_subject = '';

        if ( $tflags =~ /\bnosubject\b/ ) {
            $init_subject = '$nosubj = 1;';
            $skip_subject = 'if ($nosubj) { $nosubj = 0; next; }';
        }

        $eval .= <<"EOF";
    $dbg_running_rule
    \$test_qr = \$pms->{conf}->{ascii_rules}->{$name};
    $init_hits
    $init_subject
    rule_$loopid: foreach my \$line (\@\$ascii_body) {
        $skip_subject
        $ifwhile ( \$line =~ /\$test_qr/$modifiers ) {
            my \$match = defined \${^MATCH} ? \${^MATCH} : '<negative match>';
            $dbg_ran_rule
            \$pms->{pattern_hits}->{$name} = \$match;
            \$pms->got_hit('$name','ASCII: ','ruletype' => 'body', 'score' => $score);
            $last
        }
    }
EOF

    }
    $eval .= <<'EOF';
}

EOF

    # print "$eval\n";
    # compile the new rules
    eval untaint_var($eval);
    if ($@) {
        die("ASCII: Error compiling rules: $@");
    }

}

sub _run_ascii_rules {
    # placeholder
}

sub parsed_metadata {
    my ($self, $opts) = @_;

    $self->_run_ascii_rules($opts);

}

#
# Get the body of the message as an array of lines
#
sub _get_ascii_body {
    my ($self, $pms) = @_;

    if (exists $pms->{ascii_body}) {
        return $pms->{ascii_body};
    }

    my $msg = $pms->get_message();
    my @lines;
    foreach (@{ $msg->get_visible_rendered_body_text_array() }) {
        push @lines, convert_to_ascii($_);
    }
    $pms->{ascii_body} = \@lines;
}

sub ascii_unicode_obfuscation {
    my ($self, $pms, $body, $max_words) = @_;

    my %found;
    my $count = 0;
    ALL: for (@$body) {
        my $line = $_;
        # Make sure we have Perl chars
        unless (utf8::is_utf8($line)) {
            $line = eval { decode("UTF-8", $line) } || $line;
        }
        # Normalize the line to remove combining characters (this is important for \W in the regex below)
        $line = NFC($line);
        # Replace common ligatures (to prevent false positives)
        $line =~ s/$ligature_regex/$ligatures{$&}/g;
        # Split the line into words
        for my $word (split(/\s+/,$line)) {
            last ALL if defined $max_words && ++$count > $max_words;
            # Remove non-word characters from the beginning and end of the word
            $word =~ s/^[\W\p{M}\p{Cf}]+|[\W\p{M}\p{Cf}]+$//g;
            my $ascii = convert_to_ascii($word);
            next if $ascii eq $word;
            $ascii = lc $ascii;
            next unless exists $dictionary{$ascii};
            dbg("ascii: found obfuscated word '$ascii'");
            $found{$ascii} = 1;
        }
    }
    return scalar keys %found;
}

1;
