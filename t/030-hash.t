#!/usr/bin/env raku

use v6;

use Test;
use LibraryCheck;
use Crypt::LibScrypt;

if library-exists('scrypt', v0 ) {
    my @chars = (|("a" .. "z"), |("A" .. "Z"), |(0 .. 9));

    my $password = @chars.pick(20).join;
    my $hash;
    lives-ok { $hash = scrypt-hash($password) }, 'scrypt-hash';
    like $hash, /^'$s1$'/, 'the expected hash prefix';
    lives-ok { ok scrypt-verify($hash, $password), "verify ok" }, 'scrypt-verify';
    lives-ok { nok scrypt-verify($hash, $password.comb.reverse.join), "verify nok with wrong password" }, 'scrypt-verify';

    throws-like { scrypt-hash($password, 99) }, X::TypeCheck::Binding::Parameter, message => q{Constraint type check failed in binding to parameter '$N'; expected Crypt::LibScrypt::PowTwo but got Int (99)}, "Type check on N argument is correct";
    lives-ok { $hash = scrypt-hash($password, 32, 4, 16) }, 'scrypt-hash with some hashing parameters';
    ok scrypt-verify($hash, $password), "verify ok";
    nok scrypt-verify("ahjasHSyjjskk", $password), "not okay with any old garbage";
}
else {
    skip "No libscrypt, skipping tests";
}



done-testing;
# vim: expandtab shiftwidth=4 ft=raku
