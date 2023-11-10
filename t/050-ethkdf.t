#!/usr/bin/env raku

use v6;

use Test;
use LibraryCheck;
use Crypt::LibScrypt;
use MIME::Base64;
use Net::Ethereum;

# https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition#scrypt

constant derivedkey = '0xfac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd';

if library-exists('scrypt', v0) {
    my $password  = 'testpassword';
    my $kdfparams = {
        dklen => 32,
        n     => 262144,
        p     => 8,
        r     => 1,
        salt  => 'ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19',
    };

    my buf8 $hashbuf;
    my buf8 $saltbuf = Net::Ethereum.new.hex2buf($kdfparams<salt>);

    lives-ok { $hashbuf = scrypt-scrypt($password, $saltbuf, $kdfparams<n>, $kdfparams<r>, $kdfparams<p>) }, 'scrypt-scrypt';
    is Net::Ethereum.new.buf2hex($hashbuf.subbuf(0, $kdfparams<dklen>)).lc, derivedkey, 'derived key';
}
else {
    skip "No libscrypt, skipping tests";
}

done-testing;
# vim: expandtab shiftwidth=4 ft=raku
