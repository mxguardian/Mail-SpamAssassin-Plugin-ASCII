#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use MXG::App;
use MXG::Service::DB;
use Pod::Usage;
use XML::Parser;
use Term::ANSIColor;
use JSON;
use Encode;
use utf8;

=head1 SYNOPSIS

 unicode.pl <command> [options]

 Commands
     import_ucd           Import Unicode Character Database
     import_confusables   Import confusables from unicode.org
     decompose            Generate ASCII equivalents by decomposing characters
                          and removing combining marks
     list_homoglyphs      List homoglyphs
     list                 List all characters
     find_missing         Find missing characters
     list_ascii           List ASCII characters
     generate_map         Generate character map data for use in ASCII.pm
     test_map             Test character map
     replace_tags         Generate replace_tag code suitable for use in SpamAssassin
     explain              Decode a string of unicode characters

=cut

binmode STDOUT, ":utf8";
binmode STDERR, ":utf8";

my $kernel = MXG::App->new();
my $db = MXG::Service::DB->new(
    $kernel->config('database_host'),
    'unicode_db',
    $kernel->config('database_user'),
    $kernel->config('database_password')
);
my $dispatch = {
    'import_ucd'   => \&import_ucd,
    'decompose'    => \&decompose,
    'import_confusables'  => \&import_confusables,
    'list_homoglyphs'   => \&list_homoglyphs,
    'list'         => \&list_all,
    'find_missing' => \&find_missing,
    'list_ascii'   => \&list_ascii,
    'generate_map' => \&generate_map,
    'test_map'     => \&test_map,
    'replace_tags' => \&replace_tags,
    'explain'      => \&explain,
};

my $cmd = shift @ARGV;
pod2usage(1) unless defined($cmd);
die "Unknown command '$cmd'" unless $dispatch->{$cmd};
$dispatch->{$cmd}->();

#
# Import Unicode Character Database
#
# http://www.unicode.org/Public/UCD/latest/ucdxml/ucd.nounihan.grouped.zip
#
sub import_ucd {
    my $ins_char = $db->prepare("INSERT IGNORE INTO `char`
        (`code`,description,block,script,category,bidi_class,combining_class,
        is_upper,is_lower,is_emoji,is_whitespace,is_printable,
        decomposition,uppercase,lowercase)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");

    my $ins_special = $db->prepare("INSERT IGNORE INTO `special`
        (first_dcode,last_dcode,description) VALUES (?,?,?)");

    my $xml_file = "/home/kent/Downloads/ucd.nounihan.grouped.xml";
    my $group;
    my $xml = XML::Parser->new(Handlers => {
        Start => sub {
            my ($expat,$tag,%attr) = @_;
            if ( $tag eq 'char' ) {
                my $first_dcode;
                my $last_dcode;
                if ( defined($attr{cp}) ) {
                    $first_dcode = $last_dcode = hex($attr{cp});
                } else {
                    $first_dcode = hex($attr{'first-cp'});
                    $last_dcode = hex($attr{'last-cp'});
                }
                my $name = $attr{na} || $group->{na} || $attr{na1} || $group->{na1} || '';
                my $block = $attr{blk} || $group->{blk};
                my $script = $attr{sc} || $group->{sc};
                my $cat = $attr{gc} || $group->{gc};
                my $upper = $attr{Upper} || $group->{Upper} || 'N';
                my $lower = $attr{Lower} || $group->{Lower} || 'N';
                my $emoji = $attr{Emoji} || $group->{Emoji} || 'N';
                my $whitespace = $attr{WSpace} || $group->{WSpace} || 'N';
                my $uc = $attr{uc} || $group->{uc};
                my $lc = $attr{lc} || $group->{lc};
                my $decomp = $attr{dm} || $group->{dm};
                my $bc = $attr{bc} || $group->{bc};
                my $cc = $attr{ccc} || $group->{ccc};
                my $printable = 1;
                $printable = 0 if $cat =~ /^Cc$/;
                $printable = 0 if $bc =~ /^(BN|LR|RL|PD|FS)/;
                for (my $dcode=$first_dcode;$dcode<=$last_dcode;$dcode++) {

                    my $hcode = sprintf("%04X",$dcode);
                    my $char = chr($dcode);
                    my $desc = $name;
                    $desc =~ s/#/$hcode/;
                    $desc = $char . ' ' . $desc if $printable==1;

                    $ins_char->execute(
                        $hcode,
                        $desc,
                        $block,
                        $script,
                        $cat,
                        $bc,
                        $cc,
                        $upper eq 'Y'?1:0,
                        $lower eq 'Y'?1:0,
                        $emoji eq 'Y'?1:0,
                        $whitespace eq 'Y'?1:0,
                        $printable,
                        $decomp eq '#' ? undef: $decomp,
                        $uc eq '#' ? undef: $uc,
                        $lc eq '#' ? undef: $lc,
                    );
                } # end for

            } elsif ( $tag eq 'group' ) {
                $group = \%attr;

            } elsif ( $tag eq 'reserved' ) {
                my $first_dcode;
                my $last_dcode;
                if ( defined($attr{cp}) ) {
                    $first_dcode = $last_dcode = hex($attr{cp});
                } else {
                    $first_dcode = hex($attr{'first-cp'});
                    $last_dcode = hex($attr{'last-cp'});
                }
                $ins_special->execute($first_dcode,$last_dcode,'Reserved');

            } elsif ( $tag eq 'surrogate' ) {
                my $first_dcode;
                my $last_dcode;
                if ( defined($attr{cp}) ) {
                    $first_dcode = $last_dcode = hex($attr{cp});
                } else {
                    $first_dcode = hex($attr{'first-cp'});
                    $last_dcode = hex($attr{'last-cp'});
                }
                my $desc = $attr{blk} || 'Surrogate';
                $ins_special->execute($first_dcode,$last_dcode,$desc);

            } elsif ( $tag eq 'noncharacter' ) {
                my $first_dcode;
                my $last_dcode;
                if ( defined($attr{cp}) ) {
                    $first_dcode = $last_dcode = hex($attr{cp});
                } else {
                    $first_dcode = hex($attr{'first-cp'});
                    $last_dcode = hex($attr{'last-cp'});
                }
                $ins_special->execute($first_dcode,$last_dcode,'Non-Character');

            } # end if
        } # end start
    });

    $xml->parsefile($xml_file);

}

#
# Import Confusables
#
# http://www.unicode.org/Public/security/latest/confusables.txt
#
sub import_confusables {
    our $upd_char = $db->prepare("UPDATE `char` SET ascii_equivalent = ? WHERE code = ?");

    sub _save_confusables {
        my ($confusables) = @_;

        return unless defined($confusables) && scalar(@$confusables)>0;

        my @ascii = grep { $_ =~ /^[[:ascii:]]$/ } @$confusables;
        if ( scalar(@ascii) == 0 ) {
            # print "No ASCII equivalent for ".join(' ',@$confusables)."\n";
            return;
        }
        if ( scalar(@ascii) > 1 ) {
            print STDERR "Warning: Multiple ASCII equivalents for ".join(' ',@$confusables)."\n";
            return;
        }

        my $ascii = $ascii[0];
        print "Saving $ascii: ".join(' ',@$confusables)."\n";

        foreach my $confusable (@$confusables) {
            next if $confusable eq $ascii;
            next if length($confusable) != 1;
            my $hcode = sprintf("%04X",ord($confusable));
            # print "$hcode: $confusable -> $ascii\n";
            $upd_char->execute($ascii,$hcode);
        }
    }

    my $filename = '/tmp/confusables.txt';
    open(my $fh, '<:encoding(UTF-8)', $filename) or die "Could not open file '$filename' $!";

    my @confusables;
    foreach my $line (<$fh>) {

        # remove comments and blank lines
        $line =~ s/#.*$//;
        next if $line =~ /^\s*$/;

        # split on tabs
        my @fields = split /\t/,$line;
        # print join('|',@fields), "\n";

        # get code points and convert to characters
        my $str = $fields[2];
        next unless defined($str);
        $str =~ s/([0-9a-f]{4,6})\s*/chr(hex($1))/gei;

        if ( !$fields[0] ) {
            _save_confusables(\@confusables);
            @confusables = ();
        }
        push @confusables, $str;
    }
    _save_confusables(\@confusables);
}

sub decompose {
    our $sel_chars = $db->prepare("SELECT * FROM `char` WHERE ascii_equivalent IS NULL AND decomposition IS NOT NULL");
    our $upd_chars = $db->prepare("UPDATE `char` SET ascii_equivalent = ? WHERE code = ?");

    $sel_chars->execute();
    while (my $char = $sel_chars->fetchrow_hashref()) {
        my $ascii = _decompose($char->{decomposition});
        $ascii =~ s/[^[:ascii:]]//g;
        next unless length($ascii) && $ascii ne '()';
        print chr(hex($char->{code}))." $ascii\n";
        # $upd_chars->execute($ascii, $char->{code});
    }

    sub _decompose {
        my ($chars) = @_;
        my $base = '';
        foreach my $char (split /\s+/, $chars) {
            my $data = $db->fetch("SELECT decomposition,ascii_equivalent FROM `char` WHERE code = ?", $char);
            if ( defined($data->{decomposition}) ) {
                $base .= _decompose($data->{decomposition});
            } elsif ( defined($data->{ascii_equivalent}) ) {
                $base .= $data->{ascii_equivalent};
            } else {
                $base .= chr(hex($char));
            }
        }
        return $base;
    }

}

#
# Generate replace_tags
#
sub replace_tags {
    my $chars = $db->fetchAll("SELECT ascii_equivalent,code FROM `char` WHERE ascii_equivalent IS NOT NULL ORDER BY ascii_equivalent");
    my $re;
    my $last_ascii = '';
    foreach my $char (@$chars) {
        if ( uc($char->{ascii_equivalent}) ne $last_ascii ) {
            print "replace_tag    ${last_ascii}2    (?:$re)\n" if defined($re) && $last_ascii =~ /^[A-Z]$/;
            $last_ascii = uc($char->{ascii_equivalent});
            $re = hex_to_utf8re($char->{code});
        } else {
            $re .= '|' . hex_to_utf8re($char->{code});
        }
    }

}

#
# List of homoglyphs
#
sub list_homoglyphs {
    my $chars = $db->fetchAll("SELECT ascii_equivalent,code FROM `char` WHERE ascii_equivalent IS NOT NULL ORDER BY ascii_equivalent");
    my $str;
    my $last_ascii = '';
    foreach my $char (@$chars) {
        if ( uc($char->{ascii_equivalent}) ne $last_ascii ) {
            printf "%-6s: %s\n",${last_ascii},$str if defined($str);
            $last_ascii = uc($char->{ascii_equivalent});
            $str = chr(hex($char->{code}));
        } else {
            $str .= ' ' . chr(hex($char->{code}));
        }
    }

}

#
# List all unicode characters
#
sub list_all {
    my $chars = $db->fetchAll("SELECT * FROM `char` ORDER BY code");
    foreach my $char (@$chars) {
        my $code = $char->{code};
        # as a unicode string
        my $str = chr(hex($code));
        # utf8 in bytes
        my $utf8bytes = encode("utf8", $str);
        # utf8bytes in hex
        my $utf8hex = uc(unpack("H*", $utf8bytes));
        $utf8hex =~ s/(..)/\\x$1/g;

        my $desc = $char->{description}||'';
        printf "U+%s %-15s %s %s\n", $code, $utf8hex, $str, $desc;
    }
}

#
# List all unicode characters with ascii equivalents
#
sub list_ascii {
    my $chars = $db->fetchAll("SELECT * FROM `char` WHERE ascii_equivalent IS NOT NULL ORDER BY dcode");
    foreach my $char (@$chars) {
        my $hcode = $char->{code};
        my $str = chr(hex($hcode));
        printf "U+%s %s %s\n", $hcode, $str, $char->{ascii_equivalent};
    }
}

#
# List all unicode characters
#
sub generate_map {
    my $chars = $db->fetchAll("SELECT * FROM `char` WHERE ascii_equivalent IS NOT NULL ORDER BY dcode");
    my $count = 0;
    foreach my $char (@$chars) {
        $char->{ascii_equivalent} =~ s/\s+//g;
        next if $char->{ascii_equivalent} eq '';
        my $hcode = $char->{code};
        my $str = chr(hex($hcode));
        printf "%s %-5s", $str, uc($char->{ascii_equivalent});
        print((++$count % 20) ? ' ' : "\n");
    }
    print "\n";
}

sub test_map {

    my $test_string = <<"EOF";
    Ýou hãve a nèw vòice-mãil
    PαyPal
    You havé Reꞓeìved an Enꞓryptéd Company Maíl
    ѡѡѡ.ЬіɡЬаɡ.ϲо.zа
    A\x{030A}
    A\x{20DD}
EOF

    local $/;
    my $filename = '/home/kent/map';
    open(my $fh, '<:encoding(UTF-8)', $filename) or die "Could not open file '$filename' $!";
    my %map = split /\s+/, <$fh>;

    $test_string =~ s/([\x80-\x{10FFFF}])/defined($map{$1})?$map{$1}:$1/eg;

    # use Unicode::Normalize;
    # $test_string = NFKD($test_string);
    $test_string =~ s/\p{Combining_Mark}//g;

    print $test_string;

}

#
# Find missing characters
#
sub find_missing {

    my $special = $db->fetchAll("SELECT * FROM special ORDER BY first_dcode");
    my $chars = $db->fetchAll("SELECT dcode FROM `char` ORDER BY dcode");

    my $last_dcode = -1;
    my $c = shift(@$chars);
    my $s = shift(@$special);
    while ( defined($c) ) {
        my $dcode;
        if ( !defined($s) || $c->{dcode} < $s->{first_dcode} ) {
            $dcode = $c->{dcode};
        } else {
            $dcode = $s->{first_dcode};
        }
        if ($dcode > $last_dcode + 1) {
            my $count = $dcode - $last_dcode - 1;
            printf "Missing: U+%04X - U+%04X (%d)\n", $last_dcode + 1, $dcode - 1, $count;
        } elsif ( $dcode < $last_dcode + 1) {
            my $count = ($last_dcode + 1) - $dcode;
            printf "Overlap: U+%04X - U+%04X (%d)\n", $dcode, $last_dcode, $count;
        }
        if ( !defined($s) || $c->{dcode} < $s->{first_dcode} ) {
            $last_dcode = $dcode;
            $c = shift(@$chars);
        } else {
            $last_dcode = $s->{last_dcode};
            $s = shift(@$special);
        }
    }

}

sub explain {
    my $sel_char = $db->prepare("SELECT * FROM `char` WHERE dcode = ?");
    my $str = decode_utf8(join(' ',@ARGV));
    foreach my $char (split //,$str) {
        my $dcode = ord($char);
        $sel_char->execute($dcode);
        my $row = $sel_char->fetchrow_hashref;
        my $hcode = $row->{code};
        # print ASCII in green, others in yellow
        my $color = $dcode < 128 ? '0' : $dcode < 256 ? '33': '31';
        printf "\e[%sm%-50s U+%04X %s\e[0m\n", $color, decode_utf8($row->{description}), $dcode, hex_to_utf8re($hcode);
    }
}

sub hex_to_string {
    my $hex = shift;
    my $chars = '';
    foreach my $cp (split /\s+/,$hex) {
        $chars .= chr(hex($cp));
    }
    return $chars;
}

sub hex_to_utf8re {
    my $hex = shift;
    $hex =~ s/([0-9a-f]{4,6})\s*/chr(hex($1))/gei;
    my $bytes = encode('utf8',$hex);
    # convert bytes to re
    my $re = join('',map { sprintf('\x%02X',ord($_)) } split //,$bytes);
    return $re;
}

sub unicode_to_utf8re {
    my $unicode = shift;
    my $bytes = encode('utf8', $unicode);
    # convert bytes to re
    my $re = join('', map {sprintf('\x%02X', ord($_))} split //, $bytes);
    return $re;
}