#!/usr/bin/env perl
# Perl port of the blescope BLE pairing-audit core.
#
# PASSIVE only: reads a BLE GATT capture (JSON) from a file argument or stdin
# and reports insecure-pairing findings using the same rule IDs as the Python
# reference. It never touches a radio or a network.
#
# Depends only on JSON::PP, which ships with the Perl 5 core distribution.
#
#   perl blescope.pl capture.json          # JSON report, exit 1 if insecure
#   cat capture.json | perl blescope.pl -  # stdin
use strict;
use warnings;
use JSON::PP;

our $VERSION = "0.6.0";

my %SEVERITY_ORDER = (critical => 0, high => 1, medium => 2, low => 3, info => 4);
my %SENSITIVE = map { $_ => 1 } qw(2a56 2a57 2a58 fd5b);
my %LOCK_SERVICES = map { $_ => 1 } qw(1815 fd5a fd5b);
my @LOCK_KEYWORDS = qw(lock door bolt latch);

sub norm_uuid {
    my $s = lc(shift // "");
    $s =~ s/^\s+|\s+$//g;
    $s =~ s/0x//g;
    $s =~ s/-//g;
    if (length($s) == 32 && $s =~ /00001000800000805f9b34fb$/) {
        $s = substr($s, 4, 4);
    }
    if (length($s) > 4 && $s =~ /^0000/) {
        $s = substr($s, 4, 4);
    }
    return $s;
}

sub as_bool {
    my ($h, $k) = @_;
    return 0 unless ref($h) eq 'HASH' && exists $h->{$k};
    my $v = $h->{$k};
    return $v ? 1 : 0 if JSON::PP::is_bool($v);
    return $v ? 1 : 0;
}

sub as_str {
    my ($h, $k) = @_;
    return "" unless ref($h) eq 'HASH' && defined $h->{$k};
    my $v = $h->{$k};
    return "" if ref($v);
    return "$v";
}

sub is_lock {
    my ($cap) = @_;
    for my $g (@{ $cap->{gatt} || [] }) {
        return 1 if $LOCK_SERVICES{ norm_uuid($g->{service} // "") };
    }
    my $name = lc(as_str($cap->{device} || {}, "name"));
    for my $kw (@LOCK_KEYWORDS) {
        return 1 if index($name, $kw) >= 0;
    }
    return 0;
}

sub audit {
    my ($cap) = @_;
    my @fs;
    my $lock = is_lock($cap);
    my $smp = $cap->{smp};

    if (ref($smp) eq 'HASH' && %$smp) {
        my $method = lc(as_str($smp, "method"));
        my $mitm   = as_bool($smp, "mitm");
        my $sc     = as_bool($smp, "secure_connections");
        my $oob    = as_bool($smp, "oob");
        my $iocap  = as_str($smp, "io_capability");

        if ($method eq "just_works" || $method eq "justworks" || (!$mitm && !$oob)) {
            push @fs, { id => "SMP-JUSTWORKS", severity => ($lock ? "critical" : "high"),
                        title => "Just Works pairing (no MITM protection)" };
        }
        if (!$sc) {
            push @fs, { id => "SMP-LEGACY", severity => ($lock ? "high" : "medium"),
                        title => "LE Legacy Pairing (no Secure Connections)" };
        }
        my $ks = $smp->{max_enc_key_size};
        if (defined $ks && $ks =~ /^-?\d+$/ && $ks < 16) {
            push @fs, { id => "SMP-WEAKKEY", severity => ($ks <= 7 ? "high" : "medium"),
                        title => "Short encryption key ($ks bytes)" };
        }
        if ($iocap eq "NoInputNoOutput") {
            push @fs, { id => "SMP-IOCAP", severity => "medium",
                        title => "NoInputNoOutput I/O capability forces Just Works" };
        }
        if (as_bool($smp, "debug_keys") || lc(as_str($smp, "public_key")) eq "debug") {
            push @fs, { id => "SMP-DEBUGKEY", severity => "critical",
                        title => "Bluetooth debug keys in use" };
        }
        if (as_bool($smp, "bonding") && !$mitm
                && ($method eq "just_works" || $method eq "justworks" || $method eq "")) {
            push @fs, { id => "SMP-WEAKBOND", severity => "medium",
                        title => "Bonding stores an unauthenticated long-term key" };
        }
    } else {
        push @fs, { id => "SMP-NONE", severity => "medium",
                    title => "No pairing/security manager exchange observed" };
    }

    for my $op (@{ $cap->{att_ops} || [] }) {
        my $o = lc(as_str($op, "op"));
        next unless $o eq "write" || $o eq "write_command" || $o eq "write_request";
        my $ch = norm_uuid($op->{characteristic} // "");
        if ($SENSITIVE{$ch} && !as_bool($op, "encrypted")) {
            push @fs, { id => "ATT-PLAINTEXT-CTRL", severity => ($lock ? "critical" : "high"),
                        title => "Plaintext write to control characteristic $ch" };
        }
    }

    for my $g (@{ $cap->{gatt} || [] }) {
        my $c = $g->{characteristic};
        next unless defined $c && $c ne "";
        my $ch = norm_uuid($c);
        my %props = map { lc($_) => 1 } @{ $g->{properties} || [] };
        if ($SENSITIVE{$ch} && $props{write}
                && !$props{authenticated_write} && !$props{signed_write}) {
            push @fs, { id => "GATT-UNAUTH-WRITE", severity => ($lock ? "high" : "medium"),
                        title => "Unauthenticated writable control characteristic $ch" };
        }
    }

    @fs = sort { $SEVERITY_ORDER{$a->{severity}} <=> $SEVERITY_ORDER{$b->{severity}} } @fs;
    return @fs;
}

sub audit_text {
    my ($text) = @_;
    my $cap = JSON::PP->new->decode($text);
    die "capture JSON must be an object\n" unless ref($cap) eq 'HASH';
    my @fs = audit($cap);
    my $insecure = 0;
    $insecure = 1 if grep { $_->{severity} ne "info" } @fs;
    return (\@fs, $insecure);
}

unless (caller) {
    my $path = $ARGV[0];
    my $text;
    if (!defined $path || $path eq "-") {
        local $/; $text = <STDIN>;
    } else {
        open(my $fh, "<", $path) or do { print STDERR "error: $!\n"; exit 2; };
        local $/; $text = <$fh>; close $fh;
    }
    my ($fs, $insecure);
    eval { ($fs, $insecure) = audit_text($text); 1 }
        or do { print STDERR "error: invalid capture: $@"; exit 2; };
    my $out = JSON::PP->new->canonical->pretty->encode({
        tool => "blescope", findings => $fs,
        insecure => ($insecure ? JSON::PP::true : JSON::PP::false),
    });
    print $out;
    exit($insecure ? 1 : 0);
}

1;
