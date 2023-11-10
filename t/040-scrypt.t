#!/usr/bin/env raku

use v6;

use Test;
use LibraryCheck;
use Crypt::LibScrypt;
use MIME::Base64;

if library-exists('scrypt', v0) {
    my @chars = (|("a" .. "z"), |("A" .. "Z"), |(0 .. 9));

    for ^100 {
        my $hash;
        my $password = @chars.pick(20).join;

        my Buf[uint8] $saltbuf;
        my Buf[uint8] $hashbuf;

        lives-ok { $saltbuf = scrypt-salt }, 'scrypt-salt';
        lives-ok { $hashbuf = scrypt-scrypt($password, $saltbuf) }, 'scrypt-scrypt';
        lives-ok { $hash = scrypt-mcf(MIME::Base64.encode($saltbuf, :oneline(True)), MIME::Base64.encode($hashbuf, :oneline(True))) }, 'scrypt-mfc';
        ok scrypt-verify($hash, $password), 'verify ok';
    }
}
else {
    skip "No libscrypt, skipping tests";
}

done-testing;
# vim: expandtab shiftwidth=4 ft=raku
