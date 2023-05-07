#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use MXG::App;
use MXG::Service::DB;
use Pod::Usage;
use Data::Dumper;
use JSON;
use Encode;
use utf8;

=head1 SYNOPSIS

 tools/unicode.pl <command> [options]

 Commands
     import_ucd           Import Unicode Character Database
     decompose            Generate ASCII equivalents by decomposing characters
     import_confusables   Import confusables from unicode.org
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
    'create_schema'      => \&create_schema,
    'import_ucd'         => \&import_ucd,
    'decompose'          => \&decompose,
    'import_confusables' => \&import_confusables,
    'list_homoglyphs'    => \&list_homoglyphs,
    'list'               => \&list_all,
    'find_missing'       => \&find_missing,
    'list_ascii'         => \&list_ascii,
    'generate_map'       => \&generate_map,
    'test_map'           => \&test_map,
    'replace_tags'       => \&replace_tags,
    'explain'            => \&explain,
};

my $cmd = shift @ARGV;
pod2usage(1) unless defined($cmd);
die "Unknown command '$cmd'" unless $dispatch->{$cmd};
$dispatch->{$cmd}->();

#
# Create DB tables
#
sub create_schema {

    my @sql = split /;\s*/, <<SQL;
CREATE TABLE `chars` (
                        `hcode` char(5) NOT NULL,
                        `description` varchar(255) CHARACTER SET latin1 DEFAULT NULL,
                        `ascii` char(6) CHARACTER SET latin1 DEFAULT NULL,
                        `block` varchar(255) DEFAULT NULL,
                        `script` char(4) DEFAULT NULL,
                        `category` char(2) DEFAULT NULL,
                        `bidi_class` char(3) DEFAULT NULL,
                        `combining_class` int(4) DEFAULT NULL,
                        `is_upper` tinyint(1) NOT NULL DEFAULT '0',
                        `is_lower` tinyint(1) NOT NULL DEFAULT '0',
                        `is_emoji` tinyint(1) NOT NULL DEFAULT '0',
                        `is_whitespace` tinyint(1) NOT NULL DEFAULT '0',
                        `is_printable` tinyint(1) NOT NULL DEFAULT '1',
                        `is_zero_width` tinyint(1) NOT NULL DEFAULT '0',
                        `decomposition` varchar(255) DEFAULT NULL,
                        `uppercase` varchar(255) DEFAULT NULL,
                        `lowercase` varchar(255) DEFAULT NULL,
                        `dcode` int(11) unsigned DEFAULT NULL,
                        `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        PRIMARY KEY (`hcode`),
                        KEY `sort` (`dcode`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TRIGGER `before_ins` BEFORE INSERT ON `chars` FOR EACH ROW SET NEW.dcode = CONV(NEW.hcode,16,10);

CREATE TABLE `special` (
                           `first_dcode` int(11) unsigned NOT NULL,
                           `last_dcode` int(11) unsigned NOT NULL,
                           `description` varchar(255) DEFAULT NULL,
                           PRIMARY KEY (`first_dcode`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SQL

    for (@sql) {
        chomp;
        $db->do($_);
    }

}
#
# Import Unicode Character Database
#
# http://www.unicode.org/Public/UCD/latest/ucdxml/ucd.nounihan.grouped.zip
#
sub import_ucd {

    use LWP::UserAgent;
    use XML::Parser;
    use Archive::Zip;

    my $ins_char = $db->prepare("INSERT IGNORE INTO `chars`
        (`hcode`,description,block,script,category,bidi_class,combining_class,
        is_upper,is_lower,is_emoji,is_whitespace,is_printable,
        decomposition,uppercase,lowercase)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");

    my $ins_special = $db->prepare("INSERT IGNORE INTO `special`
        (first_dcode,last_dcode,description) VALUES (?,?,?)");

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

    my $xml_file = "/tmp/ucd.nounihan.grouped.xml";
    if ( ! -f $xml_file ) {
        my $zip_file = "/tmp/ucd.nounihan.grouped.zip";
        my $url = 'http://www.unicode.org/Public/UCD/latest/ucdxml/ucd.nounihan.grouped.zip';
        print "Downloading $url\n";
        my $ua = LWP::UserAgent->new();
        my $response = $ua->get($url, ':content_file' => $zip_file);
        die $response->status_line unless $response->is_success;

        print "Extracting to $xml_file\n";
        my $zip = Archive::Zip->new();
        $zip->read($zip_file);
        $zip->extractMember('ucd.nounihan.grouped.xml', $xml_file);
    }

    print "Importing $xml_file...This will take a Micro\$oft minute.\n";
    $xml->parsefile($xml_file);

}

#
# Import Confusables
#
# https://www.unicode.org/Public/security/latest/confusables.txt
#
sub import_confusables {

    use LWP::UserAgent;

    our $upd_char = $db->prepare("UPDATE `chars` SET ascii = ? WHERE hcode = ?");

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
        # print "Saving $ascii: ".join(' ',@$confusables)."\n";

        foreach my $confusable (@$confusables) {
            next if $confusable eq $ascii;
            next if length($confusable) != 1;
            my $hcode = sprintf("%04X",ord($confusable));
            # print "$hcode: $confusable -> $ascii\n";
            $upd_char->execute($ascii,$hcode);
        }
    }

    my $filename = '/tmp/confusables.txt';
    if ( ! -f $filename ) {
        my $url = 'https://www.unicode.org/Public/security/latest/confusables.txt';
        print "Downloading $url\n";
        my $ua = LWP::UserAgent->new;
        my $response = $ua->get($url, ':content_file' => $filename);
        die $response->status_line unless $response->is_success;
    }
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
    our $sel_chars = $db->prepare("SELECT * FROM `chars` WHERE ascii IS NULL AND decomposition IS NOT NULL");
    our $upd_chars = $db->prepare("UPDATE `chars` SET ascii = ? WHERE hcode = ?");

    print "Decomposing characters...\n";

    $sel_chars->execute();
    while (my $char = $sel_chars->fetchrow_hashref()) {
        my $ascii = _decompose($char->{decomposition});
        $ascii =~ s/[^[:ascii:]]//g;
        next unless length($ascii) && $ascii ne '()';
        # print chr(hex($char->{hcode}))." $ascii\n";
        $upd_chars->execute($ascii, $char->{hcode});
    }

    sub _decompose {
        my ($chars) = @_;
        my $base = '';
        foreach my $char (split /\s+/, $chars) {
            my $data = $db->fetch("SELECT decomposition,ascii FROM `chars` WHERE hcode = ?", $char);
            if ( defined($data->{decomposition}) ) {
                $base .= _decompose($data->{decomposition});
            } elsif ( defined($data->{ascii}) ) {
                $base .= $data->{ascii};
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
    my $chars = $db->fetchAll("SELECT ascii,hcode FROM `chars` WHERE ascii IS NOT NULL ORDER BY ascii");
    my $re;
    my $last_ascii = '';
    foreach my $char (@$chars) {
        if ( uc($char->{ascii}) ne $last_ascii ) {
            print "replace_tag    ${last_ascii}2    (?:$re)\n" if defined($re) && $last_ascii =~ /^[A-Z]$/;
            $last_ascii = uc($char->{ascii});
            $re = hex_to_utf8re($char->{hcode});
        } else {
            $re .= '|' . hex_to_utf8re($char->{hcode});
        }
    }

}

#
# List of homoglyphs
#
sub list_homoglyphs {
    my $chars = $db->fetchAll("SELECT ascii,hcode FROM `chars` WHERE ascii IS NOT NULL ORDER BY ascii");
    my $str;
    my $last_ascii = '';
    foreach my $char (@$chars) {
        if ( uc($char->{ascii}) ne $last_ascii ) {
            printf "%-6s: %s\n",${last_ascii},$str if defined($str);
            $last_ascii = uc($char->{ascii});
            $str = chr(hex($char->{hcode}));
        } else {
            $str .= ' ' . chr(hex($char->{hcode}));
        }
    }

}

#
# List all unicode characters
#
sub list_all {
    my $chars = $db->fetchAll("SELECT * FROM `chars` ORDER BY dcode");
    foreach my $char (@$chars) {
        my $hcode = $char->{hcode};
        # as a unicode string
        my $str = chr(hex($hcode));
        # utf8 in bytes
        my $utf8bytes = encode("utf8", $str);
        # utf8bytes in hex
        my $utf8hex = uc(unpack("H*", $utf8bytes));
        $utf8hex =~ s/(..)/\\x$1/g;

        my $desc = $char->{description}||'';
        printf "U+%s %-15s %s %s\n", $hcode, $utf8hex, $str, $desc;
    }
}

#
# List all unicode characters with ascii equivalents
#
sub list_ascii {
    my $chars = $db->fetchAll("SELECT * FROM `chars` WHERE ascii IS NOT NULL ORDER BY dcode");
    foreach my $char (@$chars) {
        my $hcode = $char->{hcode};
        my $str = chr(hex($hcode));
        printf "U+%s %s %s\n", $hcode, $str, $char->{ascii};
    }
}

#
# List all unicode characters
#
sub generate_map {

    my $filename = 'lib/Mail/SpamAssassin/Plugin/ASCII.pm';
    open my $fh, '+<', $filename or die "Cannot open $filename: $!";

    # Find the start of the __DATA__ section
    seek $fh, 0, 0;
    while (<$fh>) {
        last if /^__DATA__\r?\n/;
    }
    if (eof $fh) {
        # No __DATA__ section found, append one
        print $fh "__DATA__\n";
    } else {
        # Truncate the file at the start of the __DATA__ section
        truncate $fh, tell($fh);
    }

    my $chars = $db->fetchAll("SELECT * FROM `chars` WHERE ascii IS NOT NULL ORDER BY dcode");
    foreach my $char (@$chars) {
        my $hcode = $char->{hcode};
        my $ascii = $char->{ascii};
        $ascii = ' ' if ($ascii =~ /^\s*$/);  #
        $ascii = join('+', map { sprintf("%02X", ord($_)) } split //, $ascii);
        printf $fh "%s %s\n", $hcode, $ascii;
    }
    close $fh;
    print "Updated $filename with new char map\n";
}

sub test_map {

    use lib 'lib';
    use Mail::SpamAssassin::Plugin::ASCII;

    my $body = <<"EOF";
Ýou hãve a nèw vòice-mãil
PαyPal
You havé Reꞓeìved an Enꞓryptéd Company Maíl
ѡѡѡ.ЬіɡЬаɡ.ϲо.zа
A\x{030A}
A\x{20DD}
あ
The pass͏word­ for your ­em͏ail ­expi͏res
💚🍁32 Years older Div0rced🍁💚Un-happy🍁💚BJ MOM💘Ready for fu*c*k💋💘
EOF

    my %map;
    while (<Mail::SpamAssassin::Plugin::ASCII::DATA>) {
        chomp;
        my ($key,$value) = split /\s+/;
        my $ascii = join('', map { chr(hex($_)) } split /\+/, $value);
        $map{chr(hex($key))} = $ascii;
    }

    # remove zero-width characters and combining marks
    $body =~ s/[\xAD\x{034F}\x{200B}-\x{200F}\x{202A}\x{202B}\x{202C}\x{2060}\x{FEFF}]|\p{Combining_Mark}//g;

    # replace non-ascii characters with ascii equivalents
    $body =~ s/([^[:ascii:]])/defined($map{$1})?$map{$1}:' '/eg;

    # reduce spaces
    $body =~ s/\x{20}+/ /g;

    # use Unicode::Normalize;
    # $test_string = NFKD($test_string);
    # $test_string =~ s/\p{Combining_Mark}//g;

    print $body;

}

#
# Find missing characters
#
sub find_missing {

    my $special = $db->fetchAll("SELECT * FROM special ORDER BY first_dcode");
    my $chars = $db->fetchAll("SELECT dcode FROM `chars` ORDER BY dcode");

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
    my $sel_char = $db->prepare("SELECT * FROM `chars` WHERE dcode = ?");
    my $str = decode_utf8(join(' ',@ARGV));
    foreach my $char (split //,$str) {
        my $dcode = ord($char);
        $sel_char->execute($dcode);
        my $row = $sel_char->fetchrow_hashref;
        my $hcode = $row->{hcode};
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