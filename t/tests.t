use lib 'lib';
use strict;
use warnings FATAL => 'all';
use Test::More;
use Mail::SpamAssassin;

my $data_dir = 't/data';
my $spamassassin = Mail::SpamAssassin->new(
    {
        dont_copy_prefs    => 1,
        local_tests_only   => 1,
        use_bayes          => 0,
        use_razor2         => 0,
        use_pyzor          => 0,
        use_dcc            => 0,
        use_auto_whitelist => 0,
        debug              => '0',
        pre_config_text        => <<'EOF'
            loadplugin Mail::SpamAssassin::Plugin::ASCII

            ascii  ASCII_OFFICE_365  /office 365/i

            ascii  ASCII_HELP_DESK   /help desk/i

            ascii  __ASCII_VOICEMAIL   /voice-?mail/i
            tflags __ASCII_VOICEMAIL   multiple
            meta   ASCII_VOICEMAIL     __ASCII_VOICEMAIL == 3

            ascii  ASCII_BIGBAG      /www\.bigbag\.co\.za/i

            ascii  ASCII_SUBJ        /You have a new voice-?mail/i

            ascii  ASCII_NOSUBJ      /Password Notification/i
            tflags ASCII_NOSUBJ      nosubject

            ascii  __ASCII_LAWN      /lawn/i
            tflags __ASCII_LAWN      multiple maxhits=5
            meta   ASCII_LAWN        __ASCII_LAWN == 5

EOF
            ,
    }
);

my @files = (
    {
        'name'       => 'msg1.eml',
        'hits'       => {
            'ASCII_OFFICE_365' => 1,
            'ASCII_HELP_DESK' => 1,
        },
        'pattern_hits' => {
            'ASCII_OFFICE_365' => 'Office 365',
            'ASCII_HELP_DESK' => 'Help Desk',
        }
    },
    {
        'name'       => 'msg2.eml',
        'hits'       => {
            'ASCII_VOICEMAIL' => 1,
            'ASCII_SUBJ' => 1,
        },
        'pattern_hits' => {
            'ASCII_SUBJ' => 'You have a new voice-mail',
        }
    },
    {
        'name'       => 'msg3.eml',
        'hits'       => {
            'ASCII_BIGBAG' => 1,
            'ASCII_LAWN' => 1,
        },
        'pattern_hits' => {
            'ASCII_BIGBAG' => 'www.bigbag.co.za',
        }
    },
);

plan tests => scalar @files * 2;

# test each file
foreach my $file (@files) {
    print "Testing $file->{name}\n";
    my $path = "$data_dir/".$file->{name};
    open my $fh, '<', $path or die "Can't open $path: $!";
    my $msg = $spamassassin->parse($fh);
    my $pms = $spamassassin->check($msg);
    close $fh;
    delete $_->{part} for @{$pms->{attachments}};

    my $hits = $pms->get_names_of_tests_hit_with_scores_hash();
    my $pattern_hits = $pms->{pattern_hits};

    foreach my $test (keys %$hits) {
        delete $hits->{$test} unless $test =~ /^ASCII_/;
    }
    foreach my $test (keys %$pattern_hits) {
        delete $pattern_hits->{$test} unless $test =~ /^ASCII_/;
    }
    is_deeply($hits, $file->{hits}, $file->{name});
    is_deeply($pattern_hits, $file->{pattern_hits}, $file->{name});
}
