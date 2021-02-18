# Crypt::LibScrypt

Scrypt password hashing using libscrypt

![Build Status](https://github.com/jonathanstowe/Crypt-LibScrypt/workflows/CI/badge.svg)

## Synopsis


    use Crypt::LibScrypt;

    my $password =  'somepa55word';

    my $hash     =  scrypt-hash($password);

    if scrypt-verify($hash, $password ) {

        #  password ok

    }

## Description

This module provides a binding to the [scrypt](https://en.wikipedia.org/wiki/Scrypt) password hashing functions provided by [libscrypt](https://github.com/technion/libscrypt).

It is an alternative to [Crypt::SodiumScrypt](https://github.com/jonathanstowe/Crypt-SodiumScrypt) where one or other of the native libraries is already available or more easily installed.
However the two libraries may not be completely interchangeable as the hash may have a different salt prefix. You also can't use both in the same program without some care as both modules
export `scrypt-hash` and `scrypt-verify`.

The Scrypt algorithm is designed to be prohibitively expensive in terms of time and memory for a brute force attack, so is considered relatively secure. However this means that it might not be suitable for use on resource constrained systems. The *cost* parameters for `scrypt-hash` can be tuned - the defaults are a reasonable compromise though.

The hash returned by `scrypt-hash` is in the format used in `/etc/shadow` and can be verified by other libraries that understand the Scrypt algorithm ( such as the `libxcrypt` that is used for password hashing on some Linux distributions.) 

## Installation

You will need to have C<libscrypt> installed for this to work, it is commonly packaged for various Linux distributions, so you should be able
to use the usual package management tools. It can also be built from source from https://github.com/technion/libscrypt

Assuming that you have a working installation of Rakudo then you should be able to install this with *zef* :

    zef install Crypt::LibScrypt

    # Or from a local clone

    zef install .

## Support

If you any suggestions/patches feel free to send them via:

https://github.com/jonathanstowe/Crypt-LibScrypt/issues

## Licence & Copyright

This is free software please see the [LICENCE](LICENCE) file in the distribution
for details.

© Jonathan Stowe 2021

