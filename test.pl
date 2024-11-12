#!/usr/bin/perl

use Auth::Radius;

## usage

my $mschap_challenge = '0x42735ad7ac35af30';
my $mschap_response = '0x0001000000000000000000000000000000000000000000000000e7a51b90f5fa924c08941a2824417b372fcd38a3248dc7b3';
my $passwd = 'hello';

print "** MS-CHAP_V1 **\n";
print "Case 1:orig response \n$mschap_response\nwith passwd >$passwd< reply will be \n".mk_mschap_v1_response($mschap_challenge,$passwd)."\n";
print 'MS-MPPE-Keys = ';bin2hex(mppe_v1_keys($passwd)); print"\n";
print "Case 2: testing passwd >$passwd<  = ".(chk_mschap_v1($passwd,$mschap_challenge,$mschap_response) ? 'success!' : 'fail')."\n";

my $authchallenge = '0x0dbbcd1155c5a0891a23bc84dacdf1cf';
my $mschap_v2_resp = '0x00007eb0d770ae1cbcc9e101c4489c4ae9e80000000000000000cada26137d7c98359430057fe749154a4dba6a659de0110a';
my $uname = 'bob';

print "** MS-CHAP_V2 **\n";
my ($success, $send_key, $recv_key) = mk_mschap_v2_success($authchallenge, $mschap_v2_resp, $uname, $passwd);
print "Case 1: orig response\n$mschap_v2_resp\n".
	"with passwd >$passwd< reply will be \n".
	mk_mschap_v2_response($authchallenge, $mschap_v2_resp, $uname, $passwd)."\n".
	"MS-CHAP2-Success = $success\nMS-MPPE-Send-Key = $send_key\nMS-MPPE-Recv-Key = $recv_key\n".
print "Case 2: testing passwd >$passwd<  = ".(chk_mschap_v2($uname, $passwd, $authchallenge, $mschap_v2_resp) ? 'success!' : 'fail')."\n";

print "** CHAP**\n";
my $chap_password = '0x01b9523478b3fa5dfe1882be1b37596ad6';
my $chap_challenge = '0xbb1e6806a11c558328ec91653744f7d90076bce90d9f0de4e77e7124b62e6d528f';
my $passwd = '1';

print "Case 1: chap_password = $chap_password; with passwd >$passwd< will be ".mk_chap_response($chap_password,$passwd,$chap_challenge)."\n";
print "Case 2: testing passwd >$passwd<  = ".(chk_chap($chap_password,$passwd,$chap_challenge) ? 'success!' : 'fail')."\n";