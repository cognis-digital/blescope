#!/usr/bin/env perl
# Smoke + behavior tests for the Perl port. Run: perl blescope.t
use strict;
use warnings;
use Test::More tests => 14;
use FindBin qw($Bin);

require "$Bin/blescope.pl";

my $lock = <<'JSON';
{
  "device": {"name": "FrontDoorLock", "address": "AA:BB:CC:DD:EE:FF"},
  "gatt": [{"service": "1815", "characteristic": "2a56", "properties": ["read","write","notify"]}],
  "smp": {"method": "just_works", "io_capability": "NoInputNoOutput",
          "mitm": false, "secure_connections": false, "max_enc_key_size": 7},
  "att_ops": [{"op": "write", "characteristic": "2a56", "value": "01", "encrypted": false}]
}
JSON

my $secure = <<'JSON';
{
  "device": {"name": "SecureBand", "address": "11:22:33:44:55:66"},
  "gatt": [{"service": "180d", "characteristic": "2a37", "properties": ["notify"]}],
  "smp": {"method": "numeric_comparison", "io_capability": "DisplayYesNo",
          "mitm": true, "secure_connections": true, "max_enc_key_size": 16},
  "att_ops": []
}
JSON

sub ids { my %m; $m{$_->{id}} = 1 for @{$_[0]}; return \%m; }

# norm_uuid
is(main::norm_uuid("1815"), "1815", "short uuid passthrough");
is(main::norm_uuid("0x1815"), "1815", "strips 0x");
is(main::norm_uuid("0000180a-0000-1000-8000-00805f9b34fb"), "180a", "reduces 128-bit base uuid");

# insecure lock
my ($fs, $insecure) = main::audit_text($lock);
ok($insecure, "insecure lock flagged");
my $id = ids($fs);
ok($id->{"SMP-JUSTWORKS"}, "SMP-JUSTWORKS present");
ok($id->{"SMP-LEGACY"}, "SMP-LEGACY present");
ok($id->{"SMP-WEAKKEY"}, "SMP-WEAKKEY present");
ok($id->{"ATT-PLAINTEXT-CTRL"}, "ATT-PLAINTEXT-CTRL present");
is($fs->[0]{severity}, "critical", "worst-first ordering: critical leads");

# secure clean
my ($fs2, $insecure2) = main::audit_text($secure);
ok(!$insecure2, "secure capture clean");
is(scalar(@$fs2), 0, "secure capture has zero findings");

# no smp
my ($fs3) = main::audit_text('{"device":{"name":"x"},"gatt":[]}');
ok(ids($fs3)->{"SMP-NONE"}, "SMP-NONE when no smp block");

# bad json
eval { main::audit_text("not json"); };
ok($@, "bad json raises");

# array json rejected (must be object)
eval { main::audit_text("[]"); };
ok($@, "array capture rejected");
