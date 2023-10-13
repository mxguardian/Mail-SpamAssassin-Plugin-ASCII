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

This plugin defines a new rule type called C<ascii> that is used to match
against an ASCII-only version of the message body. When a message is scanned,
this plugin makes a copy of the message body, converts it to ASCII characters
and then runs rules against the converted text. This is useful for
catching spam that uses non-ASCII characters to obfuscate words. For example,
a message containing the text

    Ýou hãve a nèw vòice-mãil

would be converted to

    You have a new voice-mail

before processing the rules. The actual conversion is done by the Text::ASCII::Convert module.
See L<Text::ASCII::Convert> for details.

=head1 REQUIREMENTS

=over

=item SpamAssassin 3.4.0 or later

=item Text::ASCII::Convert

=back

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

our $VERSION = 0.99;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger qw(would_log);
use Mail::SpamAssassin::Util qw(compile_regexp &untaint_var);
use Encode;
use Text::ASCII::Convert;

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor
sub new {
    my $class = shift;
    my $mailsaobject = shift;

    # some boilerplate...
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless ($self, $class);

    $self->set_config($mailsaobject->{conf});

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

    my @lines;
    foreach (@{ $pms->get_decoded_stripped_body_text_array() }) {
        push @lines, convert_to_ascii($_);
    }
    $pms->{ascii_body} = \@lines;
}

1;
