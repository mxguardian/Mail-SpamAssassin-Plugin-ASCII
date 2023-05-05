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

# Author:  Kent Oyer <kent@mxguardian.net>

=encoding utf8

=head1 NAME

Mail::SpamAssassin::Plugin::ASCII - SpamAssassin plugin to convert non-ASCII characters to their ASCII equivalents

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::ASCII

  ascii      RULE_NAME   /You have a new voice-?mail/i
  describe   RULE_NAME   Voice mail spam
  score      RULE_NAME   1.0

=head1 DESCRIPTION

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
    You have Received an Encrypted Company Mail
    www.bigbag.co.za

Unlike other transliteration software, this plugin converts non-ASCII characters
to their ASCII equivalents based on appearance instead of meaning. For example, the
German eszett character 'ß' is converted to the Roman letter 'B' instead of 'ss'
because it resembles a 'B' in appearance. Likewise, the Greek letter Sigma ('Σ') is
converted to 'E' and a lower case Omega ('ω') is converted to 'w' even though these
letters have different meanings than their originals.

Not all non-ASCII characters are converted. For example, the Japanese Hiragana
character 'あ' is not converted because it does not resemble any ASCII character.
Characters that have no ASCII equivalent are left unchanged.

The plugin also removes zero-width characters such as the zero-width
space (U+200B) and zero-width non-joiner (U+200C) that are often used to
obfuscate words.

If you want to write rules that match against the original non-Romanized text,
you can still do so by using the standard C<body> and C<rawbody> rules. The
converted text is only used when evaluating rules that use the C<ascii> rule type.

Note that obfuscation is still possible within the ASCII character set. For example,
the letter 'O' can be replaced with the number '0' and the letter 'l' can be replaced
with the number '1' as in "PayPa1 0rder". This plugin does not attempt to catch these
types of obfuscation. Therefore, you still need to use other techniques such as using
a character class or C<replace_tags> to catch these types of obfuscation.

=cut

package Mail::SpamAssassin::Plugin::ASCII;
use strict;
use warnings FATAL => 'all';
use v5.12;
use Encode;
use Data::Dumper;
use utf8;

our $VERSION = 0.01;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger qw(would_log);
use Mail::SpamAssassin::Util qw(compile_regexp &is_valid_utf_8);

our @ISA = qw(Mail::SpamAssassin::Plugin);

my $would_log_rules_all;

# constructor
sub new {
    my $class = shift;
    my $mailsaobject = shift;

    # some boilerplate...
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless ($self, $class);

    $self->set_config($mailsaobject->{conf});
    $self->load_map();

    $would_log_rules_all = would_log('dbg', 'rules-all') == 2;

    return $self;
}

sub dbg { Mail::SpamAssassin::Logger::dbg ("ScriptInfo: @_"); }
sub info { Mail::SpamAssassin::Logger::info ("ScriptInfo: @_"); }

sub load_map {
    my ($self) = @_;

    # build character map from __DATA__ section
    local $/;
    my %char_map = split(/\s+/, <DATA>);
    $self->{char_map} = \%char_map;
    close DATA;

}

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

            }
        }
    ));

    $conf->{parser}->register_commands(\@cmds);
}

sub finish_parsing_end    {
    my ($self, $opts) = @_;

    my $conf = $opts->{conf};
    return unless exists $conf->{ascii_rules};

    # build eval string to compile rules
    my $eval = <<'EOF';
package Mail::SpamAssassin::Plugin::ASCII;

sub _run_ascii_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};
    my $test_qr;

    # check all script rules
    my $ascii_body = $self->_get_ascii_body($pms);

EOF

    foreach my $name (keys %{$conf->{ascii_rules}}) {
        my $test_qr = $conf->{ascii_rules}->{$name};
        my $tflags = $conf->{tflags}->{$name} || '';
        my $score = $conf->{scores}->{$name} || 1;

        if ( $would_log_rules_all ) {
            $eval .= qq(    dbg("running rule $name $test_qr");\n);
        }

        $eval .= <<"EOF";
    \$test_qr = \$pms->{conf}->{ascii_rules}->{$name};
    foreach my \$line (\@\$ascii_body) {
        if ( \$line =~ /\$test_qr/p ) {
EOF
        if ( $would_log_rules_all ) {
            $eval .= <<EOF;
            dbg(qq(ran rule $name ======> got hit ").(defined \${^MATCH} ? \${^MATCH} : '<negative match>').qq("));
EOF
        }
        $eval .= <<"EOF";
            \$pms->{pattern_hits}->{$name} = \${^MATCH} if defined \${^MATCH};
            \$pms->got_hit('$name','ASCII: ','ruletype' => 'body', 'score' => $score);
            last;
        }
    }
EOF
    }
    $eval .= <<'EOF';
}

sub parsed_metadata {
    my ($self, $opts) = @_;

    $self->_run_ascii_rules($opts);

}

EOF


    print $eval;
    eval $eval;
    if ($@) {
        die("Error compiling ascii rules: $@");
    }

}
#
# Get the body of the message as an array of lines
#
sub _get_ascii_body {
    my ($self, $pms) = @_;

    # locate the main body part (prefer html over text)
    my $body_part;
    foreach my $p ($pms->{msg}->find_parts(qr(text/))) {
        my ($ctype, $boundary, $charset, $name) = Mail::SpamAssassin::Util::parse_content_type($p->get_header('content-type'));

        # skip parts with a filename
        next if defined $name;

        # take the first text/html part we find
        if ( lc($ctype) eq 'text/html' ) {
            $body_part = $p;
            last;
        }

        # otherwise take the first text/plain part we find
        $body_part = $p unless defined $body_part;
    }

    # if we didn't find a text part, return empty list
    return [] unless defined $body_part;

    # get subject
    my $subject = $pms->{msg}->get_header('subject') || '';
    $subject = decode('UTF-8', $subject);

    my $body = $body_part->rendered();
    if ( is_valid_utf_8($body)) {
        $body = decode('UTF-8', $body);
    }
    $body = $subject . "\n" . $body;

    # remove zero-width characters
    $body =~ s/[\xAD\x{034F}\x{200B}-\x{200F}\x{202A}\x{202B}\x{202C}\x{2060}\x{FEFF}]//g;

    # remove combining marks
    $body =~ s/\p{Combining_Mark}//g;

    # convert spaces to ASCII 0x20
    $body =~ s/\p{Space}/ /g;

    # convert remaining chars using char map
    my $map = $self->{char_map};
    $body =~ s/([\x80-\x{10FFFF}])/defined($map->{$1}) ? $map->{$1} : $1/eg;

    # print STDERR "SUBJECT: $subject\n";
    # print STDERR "BODY: $body\n";
    my @lines = split(/\n/, $body);
    return \@lines;
}

1;

__DATA__
ª A     ² 2     ³ 3     µ U     · .     ¸ ,     ¹ 1     º O     À A     Á A     Â A     Ã A     Ä A     Å A     Æ AE    Ç C     È E     É E     Ê E     Ë E
Ì I     Í I     Î I     Ï I     Ð D     Ñ N     Ò O     Ó O     Ô O     Õ O     Ö O     × X     Ø O     Ù U     Ú U     Û U     Ü U     Ý Y     ß B     à A
á A     â A     ã A     ä A     å A     æ AE    ç C     è E     é E     ê E     ë E     ì I     í I     î I     ï I     ð O     ñ N     ò O     ó O     ô O
õ O     ö O     ø O     ù U     ú U     û U     ü U     ý Y     ÿ Y     Ā A     ā A     Ă A     ă A     Ą A     ą A     Ć C     ć C     Ĉ C     ĉ C     Ċ C
ċ C     Č C     č C     Ď D     ď D     Đ D     đ D     Ē E     ē E     Ĕ E     ĕ E     Ė E     ė E     Ę E     ę E     Ě E     ě E     Ĝ G     ĝ G     Ğ G
ğ G     Ġ G     ġ G     Ģ G     ģ G     Ĥ H     ĥ H     Ħ H     ħ H     Ĩ I     ĩ I     Ī I     ī I     Ĭ I     ĭ I     Į I     į I     İ I     ı I     Ĳ IJ
ĳ IJ    Ĵ J     ĵ J     Ķ K     ķ K     ĸ K     Ĺ L     ĺ L     Ļ L     ļ L     Ľ L     ľ L     Ŀ L     ŀ L     Ł L     ł L     Ń N     ń N     Ņ N     ņ N
Ň N     ň N     ŉ N     Ŋ N     ŋ N     Ō O     ō O     Ŏ O     ŏ O     Ő O     ő O     Œ OE    œ OE    Ŕ R     ŕ R     Ŗ R     ŗ R     Ř R     ř R     Ś S
ś S     Ŝ S     ŝ S     Ş S     ş S     Š S     š S     Ţ T     ţ T     Ť T     ť T     Ŧ T     ŧ T     Ũ U     ũ U     Ū U     ū U     Ŭ U     ŭ U     Ů U
ů U     Ű U     ű U     Ų U     ų U     Ŵ W     ŵ W     Ŷ Y     ŷ Y     Ÿ Y     Ź Z     ź Z     Ż Z     ż Z     Ž Z     ž Z     ſ F     ƀ B     Ɓ B     Ƃ B
ƃ B     Ƅ B     ƅ B     Ƈ C     ƈ C     Ɖ D     Ɗ D     Ƌ A     ƌ A     ƍ G     Ɛ E     Ƒ F     ƒ F     Ɠ G     Ɣ V     Ɩ L     Ɨ I     Ƙ K     ƙ K     ƚ L
Ɯ W     Ɲ N     ƞ N     Ɵ O     Ơ O     ơ O     Ƥ P     ƥ P     Ʀ R     Ƨ 2     ƨ 2     Ʃ E     ƫ T     Ƭ T     ƭ T     Ʈ T     Ư U     ư U     Ʊ U     Ʋ V
Ƴ Y     ƴ Y     Ƶ Z     ƶ Z     Ʒ 3     Ƹ E     ƹ E     ƻ 2     Ƽ 5     ƽ S     ƿ P     ǀ L     ǃ !     Ǆ DZ    ǅ DZ    ǆ DZ    Ǉ LJ    ǈ LJ    ǉ LJ    Ǌ NJ
ǋ NJ    ǌ NJ    Ǎ A     ǎ A     Ǐ I     ǐ I     Ǒ O     ǒ O     Ǔ U     ǔ U     Ǖ U     ǖ U     Ǘ U     ǘ U     Ǚ U     ǚ U     Ǜ U     ǜ U     Ǟ A     ǟ A
Ǡ A     ǡ A     Ǣ AE    ǣ AE    Ǥ G     ǥ G     Ǧ G     ǧ G     Ǩ K     ǩ K     Ǫ O     ǫ O     Ǭ O     ǭ O     Ǯ 3     ǯ 3     ǰ J     Ǳ DZ    ǲ DZ    ǳ DZ
Ǵ G     ǵ G     Ƕ H     Ƿ P     Ǹ N     ǹ N     Ǻ A     ǻ A     Ǽ AE    ǽ AE    Ǿ O     ǿ O     Ȁ A     ȁ A     Ȃ A     ȃ A     Ȅ E     ȅ E     Ȇ E     ȇ E
Ȉ I     ȉ I     Ȋ I     ȋ I     Ȍ O     ȍ O     Ȏ O     ȏ O     Ȑ R     ȑ R     Ȓ R     ȓ R     Ȕ U     ȕ U     Ȗ U     ȗ U     Ș S     ș S     Ț T     ț T
Ȝ 3     ȝ 3     Ȟ H     ȟ H     Ƞ N     ȡ D     Ȣ 8     ȣ 8     Ȥ Z     ȥ Z     Ȧ A     ȧ A     Ȩ E     ȩ E     Ȫ O     ȫ O     Ȭ O     ȭ O     Ȯ O     ȯ O
Ȱ O     ȱ O     Ȳ Y     ȳ Y     ȴ L     ȵ N     ȶ T     ȷ J     ȸ DB    ȹ QP    Ⱥ A     Ȼ C     ȼ C     Ƚ L     Ⱦ T     ȿ S     ɀ Z     Ɂ ?     ɂ 2     Ƀ B
Ʉ U     Ɇ E     ɇ E     Ɉ J     ɉ J     Ɋ Q     ɋ Q     Ɍ R     ɍ R     Ɏ Y     ɏ Y     ɑ A     ɓ B     ɕ C     ɖ D     ɗ D     ɛ E     ɜ 3     ɝ 3     ɞ G
ɟ J     ɠ G     ɡ G     ɢ G     ɣ Y     ɥ U     ɦ H     ɧ H     ɨ I     ɩ I     ɪ I     ɫ L     ɬ L     ɭ L     ɯ W     ɰ W     ɱ M     ɲ N     ɳ N     ɴ N
ɵ O     ɶ OE    ɼ R     ɽ R     ɾ R     ʀ R     ʂ S     ʄ F     ʈ T     ʉ U     ʋ U     ʍ M     ʏ Y     ʐ Z     ʑ Z     ʒ 3     ʓ 3     ʔ ?     ʗ C     ʘ O
ʙ B     ʛ G     ʜ H     ʝ J     ʟ L     ʠ Q     ʡ ?     ʰ H     ʲ J     ʳ R     ʷ W     ʸ Y     ʺ "     ˂ <     ˃ >     ˄ ^     ˆ ^     ː :     ˗ -     ˛ I
˜ ~     ˝ "     ˡ L     ˢ S     ˣ X     ˮ "     ˶ "     ˸ :     Ͳ T     ͳ T     Ͷ N     ͷ N     ͺ I     ͼ C     ; ;     Ϳ J     Ά A     · .     Έ E     Ή H
Ί I     Ό O     Ύ Y     ΐ I     Α A     Β B     Ε E     Ζ Z     Η H     Ι I     Κ K     Μ M     Ν N     Ο O     Ρ P     Σ E     Τ T     Υ Y     Φ O     Χ X
Ψ W     Ϊ I     Ϋ Y     ά A     έ E     ή N     ί I     ΰ U     α A     β B     γ Y     δ D     ε E     ζ Z     η N     θ O     ι I     κ K     μ U     ν V
ξ E     ο O     π N     ρ P     ς C     σ O     τ T     υ U     χ X     ψ W     ω W     ϊ I     ϋ U     ό O     ύ U     ώ W     Ϗ K     ϐ B     ϒ Y     ϓ Y
ϔ Y     ϖ N     ϗ K     Ϙ O     ϙ O     Ϛ C     ϛ C     Ϝ F     ϝ F     Ϟ S     Ϣ W     ϣ W     Ϥ 4     ϥ 4     Ϧ B     ϧ S     Ϩ 2     ϩ 2     Ϭ 6     ϭ 6
Ϯ T     ϯ T     ϰ K     ϱ P     ϲ C     ϳ J     ϴ O     ϵ E     Ϲ C     Ϻ M     ϻ M     ϼ P     Ͼ C     Ѐ E     Ѕ S     І I     Ј J     Ѝ N     А A     В B
Е E     З 3     К K     М M     Н H     О O     Р P     С C     Т T     Х X     Ь B     а A     б 6     г R     е E     к K     о O     п N     р P     с C
т T     у Y     х X     ц U     ѕ S     і I     ј J     ѝ N     ѡ W     Ѵ V     ѵ V     Ҝ K     ҝ K     Ҥ H     ҥ H     Ү Y     ү Y     ҳ X     Ҹ 4     ҹ 4
һ H     Ӏ L     ӏ I     Ӑ A     ӑ A     Ӓ A     ӓ A     Ӕ AE    ӕ AE    Ӡ 3     Ӣ N     ӣ N     Ӥ N     ӥ N     Ӧ O     ӧ O     Ӭ 3     ӭ 3     Ӯ Y     ӯ Y
Ӱ Y     ӱ Y     Ӳ Y     ӳ Y     ԁ D     Ԍ G     ԛ Q     Ԝ W     ԝ W     Յ 3     Ս U     Տ S     Օ O     ա W     գ Q     զ Q     հ H     յ J     ո N     ռ N
ս U     ց G     ք F     օ O     և U     ։ :     ׃ :     ו I     ט V     ן L     ס O     װ LL    ײ "     ״ "     ؉ %     ؊ %     ٠ .     ٥ O     ٪ %     ٫ ,
٭ *     ڬ J     ڮ J     ڶ J     ڷ J     ڸ J     ڹ U     ڽ U     ۔ .     ۰ .     ܁ .     ܂ .     ܃ :     ܄ :     ݝ E     ݞ E     ݟ E     ݫ J     ߀ O     ߊ L
ߺ _     ः :     ० O     ॽ ?     ০ O     ৪ 8     ৭ 9     ੦ O     ੧ 9     ੪ 8     ઃ :     ૦ O     ଃ 8     ଠ O     ୦ O     ୨ 9     ௐ C     ௦ O     ం O     ౦ O
ಂ O     ೦ O     ം O     ഠ O     ൦ O     ං O     ๐ O     ໐ O     ဝ O     ၀ O     ყ Y     Ꭰ D     Ꭱ R     Ꭲ T     Ꭵ I     Ꭹ Y     Ꭺ A     Ꭻ J     Ꭼ E     Ꮃ W
Ꮇ M     Ꮋ H     Ꮍ Y     Ꮐ G     Ꮒ H     Ꮓ Z     Ꮞ 4     Ꮟ B     Ꮢ R     Ꮤ W     Ꮥ S     Ꮩ V     Ꮪ S     Ꮮ L     Ꮯ C     Ꮲ P     Ꮶ K     Ꮷ J     Ᏻ G     Ᏼ B
ᐯ V     ᑌ U     ᑭ P     ᑯ D     ᒍ J     ᒪ L     ᒿ 2     ᕁ X     ᕼ H     ᕽ X     ᖇ R     ᖯ B     ᖴ F     ᗅ A     ᗞ D     ᗪ D     ᗰ M     ᗷ B     ᙭ X     ᙮ X
᜵ /     ᠃ :     ᠉ :     ᴄ C     ᴋ K     ᴏ O     ᴑ O     ᴛ T     ᴜ U     ᴠ V     ᴡ W     ᴢ Z     ᴦ R     ᴨ N     ᴬ A     ᴮ B     ᴰ D     ᴱ E     ᴳ G     ᴴ H
ᴵ I     ᴶ J     ᴷ K     ᴸ L     ᴹ M     ᴺ N     ᴼ O     ᴾ P     ᴿ R     ᵀ T     ᵁ U     ᵂ W     ᵃ A     ᵇ B     ᵈ D     ᵉ E     ᵍ G     ᵏ K     ᵐ M     ᵒ O
ᵖ P     ᵗ T     ᵘ U     ᵛ V     ᵢ I     ᵣ R     ᵤ U     ᵥ V     ᵬ B     ᵭ D     ᵮ F     ᵯ M     ᵰ N     ᵱ P     ᵲ R     ᵳ R     ᵴ S     ᵵ T     ᵶ Z     ᵻ I
ᵽ P     ᵾ U     ᶀ B     ᶁ D     ᶂ F     ᶃ G     ᶅ L     ᶆ M     ᶇ N     ᶈ P     ᶉ R     ᶊ S     ᶌ Y     ᶍ X     ᶎ Z     ᶏ A     ᶑ D     ᶒ E     ᶖ I     ᶙ U
ᶜ C     ᶠ F     ᶻ Z     Ḁ A     ḁ A     Ḃ B     ḃ B     Ḅ B     ḅ B     Ḇ B     ḇ B     Ḉ C     ḉ C     Ḋ D     ḋ D     Ḍ D     ḍ D     Ḏ D     ḏ D     Ḑ D
ḑ D     Ḓ D     ḓ D     Ḕ E     ḕ E     Ḗ E     ḗ E     Ḙ E     ḙ E     Ḛ E     ḛ E     Ḝ E     ḝ E     Ḟ F     ḟ F     Ḡ G     ḡ G     Ḣ H     ḣ H     Ḥ H
ḥ H     Ḧ H     ḧ H     Ḩ H     ḩ H     Ḫ H     ḫ H     Ḭ I     ḭ I     Ḯ I     ḯ I     Ḱ K     ḱ K     Ḳ K     ḳ K     Ḵ K     ḵ K     Ḷ L     ḷ L     Ḹ L
ḹ L     Ḻ L     ḻ L     Ḽ L     ḽ L     Ḿ M     ḿ M     Ṁ M     ṁ M     Ṃ M     ṃ M     Ṅ N     ṅ N     Ṇ N     ṇ N     Ṉ N     ṉ N     Ṋ N     ṋ N     Ṍ O
ṍ O     Ṏ O     ṏ O     Ṑ O     ṑ O     Ṓ O     ṓ O     Ṕ P     ṕ P     Ṗ P     ṗ P     Ṙ R     ṙ R     Ṛ R     ṛ R     Ṝ R     ṝ R     Ṟ R     ṟ R     Ṡ S
ṡ S     Ṣ S     ṣ S     Ṥ S     ṥ S     Ṧ S     ṧ S     Ṩ S     ṩ S     Ṫ T     ṫ T     Ṭ T     ṭ T     Ṯ T     ṯ T     Ṱ T     ṱ T     Ṳ U     ṳ U     Ṵ U
ṵ U     Ṷ U     ṷ U     Ṹ U     ṹ U     Ṻ U     ṻ U     Ṽ V     ṽ V     Ṿ V     ṿ V     Ẁ W     ẁ W     Ẃ W     ẃ W     Ẅ W     ẅ W     Ẇ W     ẇ W     Ẉ W
ẉ W     Ẋ X     ẋ X     Ẍ X     ẍ X     Ẏ Y     ẏ Y     Ẑ Z     ẑ Z     Ẓ Z     ẓ Z     Ẕ Z     ẕ Z     ẖ H     ẗ T     ẘ W     ẙ Y     ẚ A     ẛ S     ẝ F
Ạ A     ạ A     Ả A     ả A     Ấ A     ấ A     Ầ A     ầ A     Ẩ A     ẩ A     Ẫ A     ẫ A     Ậ A     ậ A     Ắ A     ắ A     Ằ A     ằ A     Ẳ A     ẳ A
Ẵ A     ẵ A     Ặ A     ặ A     Ẹ E     ẹ E     Ẻ E     ẻ E     Ẽ E     ẽ E     Ế E     ế E     Ề E     ề E     Ể E     ể E     Ễ E     ễ E     Ệ E     ệ E
Ỉ I     ỉ I     Ị I     ị I     Ọ O     ọ O     Ỏ O     ỏ O     Ố O     ố O     Ồ O     ồ O     Ổ O     ổ O     Ỗ O     ỗ O     Ộ O     ộ O     Ớ O     ớ O
Ờ O     ờ O     Ở O     ở O     Ỡ O     ỡ O     Ợ O     ợ O     Ụ U     ụ U     Ủ U     ủ U     Ứ U     ứ U     Ừ U     ừ U     Ử U     ử U     Ữ U     ữ U
Ự U     ự U     Ỳ Y     ỳ Y     Ỵ Y     ỵ Y     Ỷ Y     ỷ Y     Ỹ Y     ỹ Y     Ỿ Y     ỿ Y     ὠ W     ὡ W     ὢ W     ὣ W     ὤ W     ὥ W     ὦ W     ὧ W
ὼ W     ώ W     ᾠ W     ᾡ W     ᾢ W     ᾣ W     ᾤ W     ᾥ W     ᾦ W     ᾧ W     ι I     ῀ ~     ῲ W     ῳ W     ῴ W     ῶ W     ῷ W     ‐ -     ‑ -     ‒ -
– -     ‚ ,     “ "     ” "     ‟ "     ․ .     ‥ ..    … ...   ‰ %     ″ "     ‶ "     ‹ <     › >     ⁁ /     ⁃ -     ⁄ /     ⁎ *     ⁒ %     ⁓ ~     ⁚ :
⁰ 0     ⁱ I     ⁴ 4     ⁵ 5     ⁶ 6     ⁷ 7     ⁸ 8     ⁹ 9     ⁿ N     ₀ 0     ₁ 1     ₂ 2     ₃ 3     ₄ 4     ₅ 5     ₆ 6     ₇ 7     ₈ 8     ₉ 9     ₐ A
ₑ E     ₒ O     ₓ X     ₕ H     ₖ K     ₗ L     ₘ M     ₙ N     ₚ P     ₛ S     ₜ T     ₨ RS    ℀ %     ℁ %     ℂ C     ℃ C     ℅ %     ℆ %     ℉ OF    ℊ G
ℋ H     ℌ H     ℍ H     ℎ H     ℐ J     ℑ J     ℒ L     ℓ L     ℕ N     № NO    ℘ P     ℙ P     ℚ Q     ℛ R     ℜ R     ℝ R     ℠ SM    ℡ TEL   ™ TM    ℤ Z
ℨ Z     K K     Å A     ℬ B     ℭ C     ℮ E     ℯ E     ℰ E     ℱ F     ℳ M     ℴ O     ℹ I     ℻ FAX   ℼ N     ℽ Y     ⅀ E     ⅅ D     ⅆ D     ⅇ E     ⅈ I
ⅉ J     Ⅰ I     Ⅱ II    Ⅲ III   Ⅳ IV    Ⅴ V     Ⅵ VI    Ⅶ VII   Ⅷ VIII  Ⅸ IX    Ⅹ X     Ⅺ XI    Ⅻ XII   Ⅼ L     Ⅽ C     Ⅾ D     Ⅿ M     ⅰ I     ⅱ II    ⅲ III
ⅳ IV    ⅴ V     ⅵ VI    ⅶ VII   ⅷ VIII  ⅸ IX    ⅹ X     ⅺ XI    ⅻ XII   ⅼ L     ⅽ C     ⅾ D     ⅿ M     ∈ E     ∊ E     ∑ E     − -     ∕ /     ∖ \     ∗ *
∙ .     ∟ L     ∣ L     ∨ V     ∫ S     ∬ SS    ∶ :     ∼ ~     ⊂ C     ⋁ V     ⋃ U     ⋅ .     ⋿ E     ⍳ I     ⍴ P     ⍵ W     ⍹ W     ⍺ A     ⎸ L     ① 1
② 2     ③ 3     ④ 4     ⑤ 5     ⑥ 6     ⑦ 7     ⑧ 8     ⑨ 9     ⑩ 10    ⑪ 11    ⑫ 12    ⑬ 13    ⑭ 14    ⑮ 15    ⑯ 16    ⑰ 17    ⑱ 18    ⑲ 19    ⑳ 20    ⑴ (1)
⑵ (2)   ⑶ (3)   ⑷ (4)   ⑸ (5)   ⑹ (6)   ⑺ (7)   ⑻ (8)   ⑼ (9)   ⑽ (10)  ⑾ (11)  ⑿ (12)  ⒀ (13)  ⒁ (14)  ⒂ (15)  ⒃ (16)  ⒄ (17)  ⒅ (18)  ⒆ (19)  ⒇ (20)  ⒈ 1.
⒉ 2.    ⒊ 3.    ⒋ 4.    ⒌ 5.    ⒍ 6.    ⒎ 7.    ⒏ 8.    ⒐ 9.    ⒑ 10.   ⒒ 11.   ⒓ 12.   ⒔ 13.   ⒕ 14.   ⒖ 15.   ⒗ 16.   ⒘ 17.   ⒙ 18.   ⒚ 19.   ⒛ 20.   ⒜ A
⒝ B     ⒞ C     ⒟ D     ⒠ E     ⒡ F     ⒢ G     ⒣ H     ⒤ I     ⒥ J     ⒦ K     ⒧ L     ⒨ M     ⒩ N     ⒪ O     ⒫ P     ⒬ Q     ⒭ R     ⒮ S     ⒯ T     ⒰ U
⒱ V     ⒲ W     ⒳ X     ⒴ Y     ⒵ Z     Ⓐ A     Ⓑ B     Ⓒ C     Ⓓ D     Ⓔ E     Ⓕ F     Ⓖ G     Ⓗ H     Ⓘ I     Ⓙ J     Ⓚ K     Ⓛ L     Ⓜ M     Ⓝ N     Ⓞ O
Ⓟ P     Ⓠ Q     Ⓡ R     Ⓢ S     Ⓣ T     Ⓤ U     Ⓥ V     Ⓦ W     Ⓧ X     Ⓨ Y     Ⓩ Z     ⓐ A     ⓑ B     ⓒ C     ⓓ D     ⓔ E     ⓕ F     ⓖ G     ⓗ H     ⓘ I
ⓙ J     ⓚ K     ⓛ L     ⓜ M     ⓝ N     ⓞ O     ⓟ P     ⓠ Q     ⓡ R     ⓢ S     ⓣ T     ⓤ U     ⓥ V     ⓦ W     ⓧ X     ⓨ Y     ⓩ Z     ⓪ 0     ╱ /     ╳ X
▮ L     ▯ L     ◌ O     ⚆ O     ⚇ O     ⛣ O     ❘ L     ❙ L     ❚ L     ❨ (     ❩ )     ❮ <     ❯ >     ❲ (     ❳ )     ❴ {     ❵ }     ⟙ T     ⠁ .     ⠂ .
⠄ .     ⠐ .     ⠠ .     ⡀ .     ⢀ .     ⣀ ..    ⤫ X     ⤬ X     ⦁ .     ⧵ \     ⧸ /     ⧹ \     ⨯ X     ⬯ O     Ⱡ L     ⱡ L     Ɫ L     Ᵽ P     Ɽ R     ⱥ A
ⱦ T     Ⱨ H     ⱨ H     Ⱪ K     ⱪ K     Ⱬ Z     ⱬ Z     Ɱ M     ⱱ V     Ⱳ W     ⱳ W     ⱴ V     ⱸ E     ⱺ O     ⱼ J     ⱽ V     Ȿ S     Ɀ Z     ⲅ R     Ⲏ H
Ⲓ I     Ⲕ K     ⲕ K     Ⲙ M     Ⲛ N     Ⲟ O     ⲟ O     Ⲣ P     ⲣ P     Ⲥ C     ⲥ C     Ⲧ T     Ⲩ Y     Ⲭ X     Ⲻ -     Ⳇ /     Ⳋ 9     Ⳍ 3     Ⳑ L     Ⳓ 6
ⴸ V     ⴹ E     ⵏ I     ⵔ O     ⵝ X     ⸱ .     ⸳ .     ⼂ \     ⼃ /     〃 "     〇 O     〔 (     〕 )     〳 /     ・ .     ㇓ /     ㇔ \     ㉐ PTE   ㉑ 21    ㉒ 22
㉓ 23    ㉔ 24    ㉕ 25    ㉖ 26    ㉗ 27    ㉘ 28    ㉙ 29    ㉚ 30    ㉛ 31    ㉜ 32    ㉝ 33    ㉞ 34    ㉟ 35    ㊱ 36    ㊲ 37    ㊳ 38    ㊴ 39    ㊵ 40    ㊶ 41    ㊷ 42
㊸ 43    ㊹ 44    ㊺ 45    ㊻ 46    ㊼ 47    ㊽ 48    ㊾ 49    ㊿ 50    ㋌ HG    ㋍ ERG   ㋎ EV    ㋏ LTD   ㍱ HPA   ㍲ DA    ㍳ AU    ㍴ BAR   ㍵ OV    ㍶ PC    ㍷ DM    ㍸ DM2
㍹ DM3   ㍺ IU    ㎀ PA    ㎁ NA    ㎂ UA    ㎃ MA    ㎄ KA    ㎅ KB    ㎆ MB    ㎇ GB    ㎈ CAL   ㎉ KCAL  ㎊ PF    ㎋ NF    ㎌ UF    ㎍ UG    ㎎ MG    ㎏ KG    ㎐ HZ    ㎑ KHZ
㎒ MHZ   ㎓ GHZ   ㎔ THZ   ㎕ L     ㎖ ML    ㎗ DL    ㎘ KL    ㎙ FM    ㎚ NM    ㎛ M     ㎜ MM    ㎝ CM    ㎞ KM    ㎟ MM2   ㎠ CM2   ㎡ M2    ㎢ KM2   ㎣ MM3   ㎤ CM3   ㎥ M3
㎦ KM3   ㎨ MS2   ㎩ PA    ㎪ KPA   ㎫ MPA   ㎬ GPA   ㎭ RAD   ㎰ PS    ㎱ NS    ㎲ US    ㎳ MS    ㎴ PV    ㎵ NV    ㎶ UV    ㎷ MV    ㎸ KV    ㎹ MV    ㎺ PW    ㎻ NW    ㎼ UW
㎽ MW    ㎾ KW    ㎿ MW    ㏂ A.M.  ㏃ BQ    ㏄ CC    ㏅ CD    ㏇ CO.   ㏈ DB    ㏉ GY    ㏊ HA    ㏋ HP    ㏌ IN    ㏍ KK    ㏎ KM    ㏏ KT    ㏐ LM    ㏑ LN    ㏒ LOG   ㏓ LX
㏔ MB    ㏕ MIL   ㏖ MOL   ㏗ PH    ㏘ P.M.  ㏙ PPM   ㏚ PR    ㏛ SR    ㏜ SV    ㏝ WB    ㏿ GAL   丶 \     丿 /     ꓐ B     ꓑ P     ꓒ D     ꓓ D     ꓔ T     ꓖ G     ꓗ K
ꓙ J     ꓚ C     ꓜ Z     ꓝ F     ꓟ M     ꓠ N     ꓡ L     ꓢ S     ꓣ R     ꓦ V     ꓧ H     ꓪ W     ꓫ X     ꓬ Y     ꓮ A     ꓰ E     ꓲ I     ꓳ O     ꓴ U     ꓸ .
ꓻ .     ꓽ :     ꓿ =     ꘎ .     Ꙅ 2     ꜱ S     ꜳ AA    Ꝁ K     ꝁ K     Ꝃ K     ꝃ K     Ꝅ K     ꝅ K     Ꝉ L     ꝉ L     Ꝋ O     ꝋ O     Ꝍ O     ꝍ O     Ꝑ P
ꝑ P     Ꝓ P     ꝓ P     Ꝕ P     ꝕ P     Ꝗ Q     ꝗ Q     Ꝙ Q     ꝙ Q     Ꝛ 2     ꝛ R     Ꝟ V     ꝟ V     Ꝫ 3     Ꝯ 9     ꝸ &     ꞉ :     ꞎ L     ꞏ .     Ꞑ N
ꞑ N     Ꞓ C     ꞓ C     ꞔ C     ꞕ H     Ꞗ B     ꞗ B     Ꞙ F     ꞙ F     Ꞡ G     ꞡ G     Ꞣ K     ꞣ K     Ꞥ N     ꞥ N     Ꞧ R     ꞧ R     Ꞩ S     ꞩ S     Ɦ H
Ɬ L     Ʝ J     Ꞷ W     ꞷ W     Ꞹ U     ꞹ U     Ꞔ C     Ʂ S     Ᶎ Z     Ꟈ D     ꟈ D     Ꟊ S     ꟊ S     ꟲ C     ꟳ F     ꟴ Q     ꟹ OE    ꟾ I     ꬱ AE    ꬴ E
ꬷ L     ꬸ L     ꬹ L     ꬺ M     ꬻ N     ꬾ O     ꭇ R     ꭉ R     ꭎ U     ꭏ U     ꭒ U     ꭖ X     ꭗ X     ꭘ X     ꭙ X     ꭚ Y     ﬀ FF    ﬁ FI    ﬂ FL    ﬃ FFI
ﬄ FFL   ﬅ FT    ﬆ ST    ﬩ +     ﴾ (     ﴿ )     ︰ :     ︱ L     ︲ L     ︳ L     ︴ L     ﹍ _     ﹎ _     ﹏ _     ﹒ .     ﹘ -     ﹨ \     ﹩ $     ﹪ %     ﹫ @
！ !     ＂ "     ＃ #     ＄ $     ％ %     ＆ &     ＊ *     － -     ． .     ／ /     ０ 0     １ 1     ２ 2     ３ 3     ４ 4     ５ 5     ６ 6     ７ 7     ８ 8     ９ 9
： :     ； ;     ？ ?     ＠ @     Ａ A     Ｂ B     Ｃ C     Ｄ D     Ｅ E     Ｆ F     Ｇ G     Ｈ H     Ｉ I     Ｊ J     Ｋ K     Ｌ L     Ｍ M     Ｎ N     Ｏ O     Ｐ P
Ｑ Q     Ｒ R     Ｓ S     Ｔ T     Ｕ U     Ｖ V     Ｗ W     Ｘ X     Ｙ Y     Ｚ Z     ［ (     ＼ \     ］ )     ＾ ^     ＿ _     ｀ `     ａ A     ｂ B     ｃ C     ｄ D
ｅ E     ｆ F     ｇ G     ｈ H     ｉ I     ｊ J     ｋ K     ｌ L     ｍ M     ｎ N     ｏ O     ｐ P     ｑ Q     ｒ R     ｓ S     ｔ T     ｕ U     ｖ V     ｗ W     ｘ X
ｙ Y     ｚ Z     ｛ {     ｝ }     ･ .     ￨ L     𐞥 Q     𐩐 .     𛰍 D     𝅭 .     𝐀 A     𝐁 B     𝐂 C     𝐃 D     𝐄 E     𝐅 F     𝐆 G     𝐇 H     𝐈 I     𝐉 J
𝐊 K     𝐋 L     𝐌 M     𝐍 N     𝐎 O     𝐏 P     𝐐 Q     𝐑 R     𝐒 S     𝐓 T     𝐔 U     𝐕 V     𝐖 W     𝐗 X     𝐘 Y     𝐙 Z     𝐚 A     𝐛 B     𝐜 C     𝐝 D
𝐞 E     𝐟 F     𝐠 G     𝐡 H     𝐢 I     𝐣 J     𝐤 K     𝐥 L     𝐦 M     𝐧 N     𝐨 O     𝐩 P     𝐪 Q     𝐫 R     𝐬 S     𝐭 T     𝐮 U     𝐯 V     𝐰 W     𝐱 X
𝐲 Y     𝐳 Z     𝐴 A     𝐵 B     𝐶 C     𝐷 D     𝐸 E     𝐹 F     𝐺 G     𝐻 H     𝐼 I     𝐽 J     𝐾 K     𝐿 L     𝑀 M     𝑁 N     𝑂 O     𝑃 P     𝑄 Q     𝑅 R
𝑆 S     𝑇 T     𝑈 U     𝑉 V     𝑊 W     𝑋 X     𝑌 Y     𝑍 Z     𝑎 A     𝑏 B     𝑐 C     𝑑 D     𝑒 E     𝑓 F     𝑔 G     𝑖 I     𝑗 J     𝑘 K     𝑙 L     𝑚 M
𝑛 N     𝑜 O     𝑝 P     𝑞 Q     𝑟 R     𝑠 S     𝑡 T     𝑢 U     𝑣 V     𝑤 W     𝑥 X     𝑦 Y     𝑧 Z     𝑨 A     𝑩 B     𝑪 C     𝑫 D     𝑬 E     𝑭 F     𝑮 G
𝑯 H     𝑰 I     𝑱 J     𝑲 K     𝑳 L     𝑴 M     𝑵 N     𝑶 O     𝑷 P     𝑸 Q     𝑹 R     𝑺 S     𝑻 T     𝑼 U     𝑽 V     𝑾 W     𝑿 X     𝒀 Y     𝒁 Z     𝒂 A
𝒃 B     𝒄 C     𝒅 D     𝒆 E     𝒇 F     𝒈 G     𝒉 H     𝒊 I     𝒋 J     𝒌 K     𝒍 L     𝒎 M     𝒏 N     𝒐 O     𝒑 P     𝒒 Q     𝒓 R     𝒔 S     𝒕 T     𝒖 U
𝒗 V     𝒘 W     𝒙 X     𝒚 Y     𝒛 Z     𝒜 A     𝒞 C     𝒟 D     𝒢 G     𝒥 J     𝒦 K     𝒩 N     𝒪 O     𝒫 P     𝒬 Q     𝒮 S     𝒯 T     𝒰 U     𝒱 V     𝒲 W
𝒳 X     𝒴 Y     𝒵 Z     𝒶 A     𝒷 B     𝒸 C     𝒹 D     𝒻 F     𝒽 H     𝒾 I     𝒿 J     𝓀 K     𝓁 L     𝓂 M     𝓃 N     𝓅 P     𝓆 Q     𝓇 R     𝓈 S     𝓉 T
𝓊 U     𝓋 V     𝓌 W     𝓍 X     𝓎 Y     𝓏 Z     𝓐 A     𝓑 B     𝓒 C     𝓓 D     𝓔 E     𝓕 F     𝓖 G     𝓗 H     𝓘 I     𝓙 J     𝓚 K     𝓛 L     𝓜 M     𝓝 N
𝓞 O     𝓟 P     𝓠 Q     𝓡 R     𝓢 S     𝓣 T     𝓤 U     𝓥 V     𝓦 W     𝓧 X     𝓨 Y     𝓩 Z     𝓪 A     𝓫 B     𝓬 C     𝓭 D     𝓮 E     𝓯 F     𝓰 G     𝓱 H
𝓲 I     𝓳 J     𝓴 K     𝓵 L     𝓶 M     𝓷 N     𝓸 O     𝓹 P     𝓺 Q     𝓻 R     𝓼 S     𝓽 T     𝓾 U     𝓿 V     𝔀 W     𝔁 X     𝔂 Y     𝔃 Z     𝔄 A     𝔅 B
𝔇 D     𝔈 E     𝔉 F     𝔊 G     𝔍 J     𝔎 K     𝔏 L     𝔐 M     𝔑 N     𝔒 O     𝔓 P     𝔔 Q     𝔖 S     𝔗 T     𝔘 U     𝔙 V     𝔚 W     𝔛 X     𝔜 Y     𝔞 A
𝔟 B     𝔠 C     𝔡 D     𝔢 E     𝔣 F     𝔤 G     𝔥 H     𝔦 I     𝔧 J     𝔨 K     𝔩 L     𝔪 M     𝔫 N     𝔬 O     𝔭 P     𝔮 Q     𝔯 R     𝔰 S     𝔱 T     𝔲 U
𝔳 V     𝔴 W     𝔵 X     𝔶 Y     𝔷 Z     𝔸 A     𝔹 B     𝔻 D     𝔼 E     𝔽 F     𝔾 G     𝕀 I     𝕁 J     𝕂 K     𝕃 L     𝕄 M     𝕆 O     𝕊 S     𝕋 T     𝕌 U
𝕍 V     𝕎 W     𝕏 X     𝕐 Y     𝕒 A     𝕓 B     𝕔 C     𝕕 D     𝕖 E     𝕗 F     𝕘 G     𝕙 H     𝕚 I     𝕛 J     𝕜 K     𝕝 L     𝕞 M     𝕟 N     𝕠 O     𝕡 P
𝕢 Q     𝕣 R     𝕤 S     𝕥 T     𝕦 U     𝕧 V     𝕨 W     𝕩 X     𝕪 Y     𝕫 Z     𝕬 A     𝕭 B     𝕮 C     𝕯 D     𝕰 E     𝕱 F     𝕲 G     𝕳 H     𝕴 I     𝕵 J
𝕶 K     𝕷 L     𝕸 M     𝕹 N     𝕺 O     𝕻 P     𝕼 Q     𝕽 R     𝕾 S     𝕿 T     𝖀 U     𝖁 V     𝖂 W     𝖃 X     𝖄 Y     𝖅 Z     𝖆 A     𝖇 B     𝖈 C     𝖉 D
𝖊 E     𝖋 F     𝖌 G     𝖍 H     𝖎 I     𝖏 J     𝖐 K     𝖑 L     𝖒 M     𝖓 N     𝖔 O     𝖕 P     𝖖 Q     𝖗 R     𝖘 S     𝖙 T     𝖚 U     𝖛 V     𝖜 W     𝖝 X
𝖞 Y     𝖟 Z     𝖠 A     𝖡 B     𝖢 C     𝖣 D     𝖤 E     𝖥 F     𝖦 G     𝖧 H     𝖨 I     𝖩 J     𝖪 K     𝖫 L     𝖬 M     𝖭 N     𝖮 O     𝖯 P     𝖰 Q     𝖱 R
𝖲 S     𝖳 T     𝖴 U     𝖵 V     𝖶 W     𝖷 X     𝖸 Y     𝖹 Z     𝖺 A     𝖻 B     𝖼 C     𝖽 D     𝖾 E     𝖿 F     𝗀 G     𝗁 H     𝗂 I     𝗃 J     𝗄 K     𝗅 L
𝗆 M     𝗇 N     𝗈 O     𝗉 P     𝗊 Q     𝗋 R     𝗌 S     𝗍 T     𝗎 U     𝗏 V     𝗐 W     𝗑 X     𝗒 Y     𝗓 Z     𝗔 A     𝗕 B     𝗖 C     𝗗 D     𝗘 E     𝗙 F
𝗚 G     𝗛 H     𝗜 I     𝗝 J     𝗞 K     𝗟 L     𝗠 M     𝗡 N     𝗢 O     𝗣 P     𝗤 Q     𝗥 R     𝗦 S     𝗧 T     𝗨 U     𝗩 V     𝗪 W     𝗫 X     𝗬 Y     𝗭 Z
𝗮 A     𝗯 B     𝗰 C     𝗱 D     𝗲 E     𝗳 F     𝗴 G     𝗵 H     𝗶 I     𝗷 J     𝗸 K     𝗹 L     𝗺 M     𝗻 N     𝗼 O     𝗽 P     𝗾 Q     𝗿 R     𝘀 S     𝘁 T
𝘂 U     𝘃 V     𝘄 W     𝘅 X     𝘆 Y     𝘇 Z     𝘈 A     𝘉 B     𝘊 C     𝘋 D     𝘌 E     𝘍 F     𝘎 G     𝘏 H     𝘐 I     𝘑 J     𝘒 K     𝘓 L     𝘔 M     𝘕 N
𝘖 O     𝘗 P     𝘘 Q     𝘙 R     𝘚 S     𝘛 T     𝘜 U     𝘝 V     𝘞 W     𝘟 X     𝘠 Y     𝘡 Z     𝘢 A     𝘣 B     𝘤 C     𝘥 D     𝘦 E     𝘧 F     𝘨 G     𝘩 H
𝘪 I     𝘫 J     𝘬 K     𝘭 L     𝘮 M     𝘯 N     𝘰 O     𝘱 P     𝘲 Q     𝘳 R     𝘴 S     𝘵 T     𝘶 U     𝘷 V     𝘸 W     𝘹 X     𝘺 Y     𝘻 Z     𝘼 A     𝘽 B
𝘾 C     𝘿 D     𝙀 E     𝙁 F     𝙂 G     𝙃 H     𝙄 I     𝙅 J     𝙆 K     𝙇 L     𝙈 M     𝙉 N     𝙊 O     𝙋 P     𝙌 Q     𝙍 R     𝙎 S     𝙏 T     𝙐 U     𝙑 V
𝙒 W     𝙓 X     𝙔 Y     𝙕 Z     𝙖 A     𝙗 B     𝙘 C     𝙙 D     𝙚 E     𝙛 F     𝙜 G     𝙝 H     𝙞 I     𝙟 J     𝙠 K     𝙡 L     𝙢 M     𝙣 N     𝙤 O     𝙥 P
𝙦 Q     𝙧 R     𝙨 S     𝙩 T     𝙪 U     𝙫 V     𝙬 W     𝙭 X     𝙮 Y     𝙯 Z     𝙰 A     𝙱 B     𝙲 C     𝙳 D     𝙴 E     𝙵 F     𝙶 G     𝙷 H     𝙸 I     𝙹 J
𝙺 K     𝙻 L     𝙼 M     𝙽 N     𝙾 O     𝙿 P     𝚀 Q     𝚁 R     𝚂 S     𝚃 T     𝚄 U     𝚅 V     𝚆 W     𝚇 X     𝚈 Y     𝚉 Z     𝚊 A     𝚋 B     𝚌 C     𝚍 D
𝚎 E     𝚏 F     𝚐 G     𝚑 H     𝚒 I     𝚓 J     𝚔 K     𝚕 L     𝚖 M     𝚗 N     𝚘 O     𝚙 P     𝚚 Q     𝚛 R     𝚜 S     𝚝 T     𝚞 U     𝚟 V     𝚠 W     𝚡 X
𝚢 Y     𝚣 Z     𝚤 I     𝚥 J     𝚨 A     𝚩 B     𝚬 E     𝚭 Z     𝚮 H     𝚰 I     𝚱 K     𝚳 M     𝚴 N     𝚶 O     𝚸 P     𝚻 T     𝚼 Y     𝚾 X     𝛂 A     𝛄 Y
𝛊 I     𝛋 K     𝛎 V     𝛐 O     𝛑 N     𝛒 P     𝛔 O     𝛕 T     𝛖 U     𝛚 W     𝛞 K     𝛠 P     𝛡 N     𝛢 A     𝛣 B     𝛦 E     𝛧 Z     𝛨 H     𝛪 I     𝛫 K
𝛭 M     𝛮 N     𝛰 O     𝛲 P     𝛵 T     𝛶 Y     𝛸 X     𝛼 A     𝛾 Y     𝜄 I     𝜅 K     𝜈 V     𝜊 O     𝜋 N     𝜌 P     𝜎 O     𝜏 T     𝜐 U     𝜔 W     𝜘 K
𝜚 P     𝜛 N     𝜜 A     𝜝 B     𝜠 E     𝜡 Z     𝜢 H     𝜤 I     𝜥 K     𝜧 M     𝜨 N     𝜪 O     𝜬 P     𝜯 T     𝜰 Y     𝜲 X     𝜶 A     𝜸 Y     𝜾 I     𝜿 K
𝝂 V     𝝄 O     𝝅 N     𝝆 P     𝝈 O     𝝉 T     𝝊 U     𝝎 W     𝝒 K     𝝔 P     𝝕 N     𝝖 A     𝝗 B     𝝚 E     𝝛 Z     𝝜 H     𝝞 I     𝝟 K     𝝡 M     𝝢 N
𝝤 O     𝝦 P     𝝩 T     𝝪 Y     𝝬 X     𝝰 A     𝝲 Y     𝝸 I     𝝹 K     𝝼 V     𝝾 O     𝝿 N     𝞀 P     𝞂 O     𝞃 T     𝞄 U     𝞈 W     𝞌 K     𝞎 P     𝞏 N
𝞐 A     𝞑 B     𝞔 E     𝞕 Z     𝞖 H     𝞘 I     𝞙 K     𝞛 M     𝞜 N     𝞞 O     𝞠 P     𝞣 T     𝞤 Y     𝞦 X     𝞪 A     𝞬 Y     𝞲 I     𝞳 K     𝞶 V     𝞸 O
𝞹 N     𝞺 P     𝞼 O     𝞽 T     𝞾 U     𝟂 W     𝟆 K     𝟈 P     𝟉 N     𝟊 F     𝟎 0     𝟏 1     𝟐 2     𝟑 3     𝟒 4     𝟓 5     𝟔 6     𝟕 7     𝟖 8     𝟗 9
𝟘 0     𝟙 1     𝟚 2     𝟛 3     𝟜 4     𝟝 5     𝟞 6     𝟟 7     𝟠 8     𝟡 9     𝟢 0     𝟣 1     𝟤 2     𝟥 3     𝟦 4     𝟧 5     𝟨 6     𝟩 7     𝟪 8     𝟫 9
𝟬 0     𝟭 1     𝟮 2     𝟯 3     𝟰 4     𝟱 5     𝟲 6     𝟳 7     𝟴 8     𝟵 9     𝟶 0     𝟷 1     𝟸 2     𝟹 3     𝟺 4     𝟻 5     𝟼 6     𝟽 7     𝟾 8     𝟿 9
𝼉 T     𝼑 L     𝼓 L     𝼖 R     𝼚 I     𝼛 O     𝼝 C     𝼞 S     𝼥 D     𝼦 L     𝼧 N     𝼨 R     𝼩 S     𝼪 T     🄀 0.    🄁 0,    🄂 1,    🄃 2,    🄄 3,    🄅 4,
🄆 5,    🄇 6,    🄈 7,    🄉 8,    🄊 9,    🄐 A     🄑 B     🄒 C     🄓 D     🄔 E     🄕 F     🄖 G     🄗 H     🄘 I     🄙 J     🄚 K     🄛 L     🄜 M     🄝 N     🄞 O
🄟 P     🄠 Q     🄡 R     🄢 S     🄣 T     🄤 U     🄥 V     🄦 W     🄧 X     🄨 Y     🄩 Z     🄪 S     🄫 C     🄬 R     🄭 CD    🄮 WZ    🄰 A     🄱 B     🄲 C     🄳 D
🄴 E     🄵 F     🄶 G     🄷 H     🄸 I     🄹 J     🄺 K     🄻 L     🄼 M     🄽 N     🄾 O     🄿 P     🅀 Q     🅁 R     🅂 S     🅃 T     🅄 U     🅅 V     🅆 W     🅇 X
🅈 Y     🅉 Z     🅊 HV    🅋 MV    🅌 SD    🅍 SS    🅎 PPV   🅏 WC    🅪 MC    🅫 MD    🅬 MR    🆐 DJ    🯰 0     🯱 1     🯲 2     🯳 3     🯴 4     🯵 5     🯶 6     🯷 7
🯸 8     🯹 9
