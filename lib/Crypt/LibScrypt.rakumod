use v6;

use NativeCall;

use NativeHelpers::Array;

=begin pod

=head1  NAME

Crypt::LibScrypt - scrypt password hashing using libscrypt


=head1 SYNOPSIS

=begin code

use Crypt::LibScrypt;

my $password =  'somepa55word';

my $hash     =  scrypt-hash($password);

if scrypt-verify($hash, $password ) {

    #  password ok

}

=end code

=head1 DESCRIPTION

This module provides a binding to the
L<scrypt|https://en.wikipedia.org/wiki/Scrypt> password hashing functions
provided by L<libscrypt|https://github.com/technion/libscrypt>.

The Scrypt algorithm is designed to be prohibitively expensive in terms
of time and memory for a brute force attack, so is considered relatively
secure. However this means that it might not be suitable for use on
resource constrained systems.

The hash returned by C<scrypt-hash> is in the format used in
C</etc/shadow> and can be verified by other libraries that understand the
Scrypt algorithm ( such as the C<libxcrypt> that is used for password
hashing on some Linux distributions.)

C<scrypt-hash> takes three optional positional arguments that control the I<cost> of
the hashing, the defaults are those suggested by the library, however they
may be too strong for some applications:

=item $N CPU AND RAM cost (first modifier)

This must be a power of two greater than one. The default is 16384, typically
you only need to change this to modify the performance

=item $r RAM Cost

This has a default of 8

=item $p CPU cost (parallelisation)

This has a default of 1 which differs from the default constant in the library
but is the value suggested in the comments in the header file.

C<$r> and C<$p> typically only need adjusting if you want to adjust the
ratio between RAM and CPU.

The C<scrypt-verify> may not be able to verify passwords against Scrypt
hashes produced by other libraries (that is the hash has the prefix
I<$7$>, whereas this library will generate I<$s1$>. )

=end pod

module Crypt::LibScrypt {


    constant LIB =  [ 'scrypt', v0 ];

    constant SCRYPT_MCF_LEN = 128;
    constant SCRYPT_N       = 16384;
    constant SCRYPT_r       = 8;
    constant SCRYPT_p       = 1;


    sub libscrypt_hash(CArray[uint8] $out, Str $password, uint32 $N, uint8 $r, uint8 $p --> int32) is native(LIB) { * }

    subset PowTwo of Int where { $_ > 1 && (ceiling(log2($_)) == floor(log2($_))) };

    sub scrypt-hash(Str $password, PowTwo $N = SCRYPT_N, Int $r = SCRYPT_r, Int $p = SCRYPT_p -->  Str ) is export {

        my $hashed        = CArray[uint8].allocate(SCRYPT_MCF_LEN);

        if !libscrypt_hash($hashed, $password, $N, $r, $p) {
            die 'out of memory in scrypt-hash';
        }

        my $buf = copy-carray-to-buf($hashed, SCRYPT_MCF_LEN);
        $buf.decode.subst(/\0+$/,'');
    }

    sub libscrypt_check(Str $hash, Str $password --> int32) is native(LIB) { * }

    sub scrypt-verify(Str $hash, Str $password --> Bool ) is export {
        ?libscrypt_check($hash, $password);
    }
}

# vim: ft=raku
