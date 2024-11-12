package Auth::Radius;

use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(chk_mschap_v1 mk_mschap_v1_response 
							chk_mschap_v2 mk_mschap_v2_response 
							chk_chap mk_chap_response mk_mschap_v2_success 
							mppe_v1_keys bin2hex);

{
use strict;
use Digest::MD4 qw(md4 md4_hex);
use Crypt::DES;
use Encode;
use Digest::SHA1;
use Digest::MD5 qw(md5 md5_hex);

# ===== start common mschap crap =====
# password is 0 to 14 chars
sub LmPasswordHash {
	my $ucpw = uc($_[0]) . "\0" x (14 - length($_[0]));
	return DesHash(substr($ucpw, 0, 7)) . DesHash(substr($ucpw, 7, 7));
}

sub DesHash {
	return DesEncrypt('KGS!@#$%', $_[0]);
}

sub ChallengeResponse {
	my ($challenge, $pwhash) = @_;
	my $zpwhash = $pwhash . "\0" x (21 - length($pwhash));
	return DesEncrypt($challenge, substr($zpwhash, 0, 7)) . DesEncrypt($challenge, substr($zpwhash, 7, 7)) . DesEncrypt($challenge, substr($zpwhash, 14, 7));
}

sub NtPasswordHash {
	return md4(encode('UCS-2LE',$_[0]));
}

sub NtChallengeResponse {
	my ($challenge, $password) = @_;
	return ChallengeResponse($challenge, NtPasswordHash($password));
}

sub DesParity {
	my ($key) = @_;
	my $ks = unpack('B*', $key);
	my ($index, $pkey);
	foreach $index (0 .. 7) {
		$pkey .= pack('B*', substr($ks, $index * 7, 7) . '0'); # parity bit is 0
	}
	return $pkey;
}

sub DesEncrypt {
	my ($clear, $key) = @_;
	$key = DesParity($key);
	my $cipher = new Crypt::DES $key;
	return $cipher->encrypt($clear);
}

# MSCHAP V2 support:
my $magic1 = pack('H*', '4D616769632073657276657220746F20636C69656E74207369676E696E6720636F6E7374616E74');
my $magic2 = pack('H*', '50616420746F206D616B6520697420646F206D6F7265207468616E206F6E6520697465726174696F6E');

sub GenerateNTResponse {
	my ($authchallenge, $peerchallenge, $username, $password) = @_;
	my $challenge = ChallengeHash($peerchallenge, $authchallenge, $username);
	my $passwordhash = NtPasswordHash($password);
	my $response = ChallengeResponse($challenge, $passwordhash);
	return $response;
}

sub ChallengeHash {
	my ($peerchallenge, $authchallenge, $username) = @_;
	return substr(Digest::SHA1::sha1($peerchallenge . $authchallenge . $username ), 0, 8);
}

sub GenerateAuthenticatorResponseHash {
	my ($pwhashhash, $ntresponse, $peerchallenge, $authchallenge, $username) = @_;
	my $digest = Digest::SHA1::sha1($pwhashhash . $ntresponse . $magic1);
	my $challenge = ChallengeHash($peerchallenge, $authchallenge, $username);
	$digest = Digest::SHA1::sha1($digest . $challenge . $magic2);
	return "S=" . uc(unpack('H*', $digest));
}

# MPPE keys
sub mppe_v1_keys {
	my ($pw,$request_authenticator) = @_;
	my $lm_key = substr(LmPasswordHash($pw), 0, 8);
	my $nt_key = substr(md4(NtPasswordHash($pw)), 0, 16);
	return $lm_key . $nt_key . "\0"x8;
}

my $SHSpad1 = "\x00" x 40;
my $SHSpad2 = "\xf2" x 40;
my $mppeMagic1 = pack('H*', '5468697320697320746865204d505045204d6173746572204b6579');
my $mppeMagic2 = pack('H*', '4f6e2074686520636c69656e7420736964652c2074686973206973207468652073656e64206b65793b206f6e207468652073657276657220736964652c206974206973207468652072656365697665206b65792e');
my $mppeMagic3 = pack('H*', '4f6e2074686520636c69656e7420736964652c2074686973206973207468652072656365697665206b65793b206f6e207468652073657276657220736964652c206974206973207468652073656e64206b65792e');

sub mppe_v2_send_key {
	my ($nt_hashhash, $nt_response, $requiredlen) = @_;
	my $masterkey = GetMasterKey($nt_hashhash, $nt_response);
	return (
		GetAsymmetricStartKey($masterkey, $requiredlen, 1, 1),
		GetAsymmetricStartKey($masterkey, $requiredlen, 0, 1)
	);
}

sub GetMasterKey {
	my ($nt_hashhash, $nt_response) = @_;
	require Digest::SHA1;
	return substr(Digest::SHA1::sha1($nt_hashhash . $nt_response . $mppeMagic1), 0, 16);
}

sub GetAsymmetricStartKey {
	my ($masterkey, $requiredlen, $issend, $isserver) = @_;
	my $s = ($issend ^ $isserver) ? $mppeMagic2 : $mppeMagic3;
	require Digest::SHA1;
	return substr(Digest::SHA1::sha1($masterkey . $SHSpad1 . $s . $SHSpad2), 0, $requiredlen);
}

# ===== end common mschap crap =====
# variant 1
sub mk_chap_response {
	my ($chap_id, $passwd, $challenge) = @_;
	$chap_id =~ s/^0x//;
	$chap_id = substr($chap_id, 0, 2);
	$challenge =~ s/^0x//;
	return '0x'.$chap_id.md5_hex(pack('H*',$chap_id).$passwd.pack('H*',$challenge));
}

sub mk_mschap_v1_response {
	my ($challenge, $passwd) = @_;
	$challenge =~ s/^0x//;
	$challenge = pack('H*',$challenge);
	return '0x0001'.'0'x48 .unpack('H*', NtChallengeResponse($challenge,$passwd) );
}

sub mk_mschap_v2_response {
	my ($authchallenge, $response, $uname, $passwd) = @_;
	$authchallenge =~ s/^0x//;
	$authchallenge = pack('H*',$authchallenge);
	$response =~ s/^0x//;
	my $peerchallenge = substr($response, 4, 32);
	my $bpc = pack('H*',$peerchallenge);
	my $nt_response = GenerateNTResponse($authchallenge, $bpc, $uname, $passwd);
	return '0x0000'.$peerchallenge.'0000000000000000'.unpack('H*', GenerateNTResponse($authchallenge, $bpc, $uname, $passwd) );
}

sub mk_mschap_v2_success {
	my ($authchallenge, $response, $uname, $passwd) = @_;
	$authchallenge =~ s/^0x//;
	$authchallenge = pack('H*',$authchallenge);
	$response =~ s/^0x//;
	my $peerchallenge = substr($response, 4, 32);
	my $bpc = pack('H*',$peerchallenge);
	my $nt_response = GenerateNTResponse($authchallenge, $bpc, $uname, $passwd);
	my $nt_hashhash = md4(NtPasswordHash($passwd));
	my ($send_key, $recv_key) = mppe_v2_send_key($nt_hashhash, $nt_response, 16);
	my $success = GenerateAuthenticatorResponseHash(md4(NtPasswordHash($passwd)), $nt_response, $bpc, $authchallenge, $uname);
	return ( '0x00'.unpack('H*', $success), '0x00'.unpack('H*', $send_key), '0x00'.unpack('H*', $recv_key) );
}

# variant 2
sub chk_mschap_v1 {
	my ($passwd, $chap_challenge, $chap_resp) = @_;
	$chap_challenge =~ s/^0x//;
	$chap_resp =~ s/^0x//;
	my $chap_nt_hash = substr($chap_resp, 52, 48);
	my $ret = unpack('H*', NtChallengeResponse(pack('H*',$chap_challenge),$passwd) );
	return $chap_nt_hash eq $ret;
}

sub chk_mschap_v2 {
	my ($uname, $passwd, $authchallenge, $response) = @_;
	$authchallenge =~ s/^0x//;
	$response =~ s/^0x//;
	my $chap_peer_challenge = substr($response, 4, 32);
	my $chap_ntv2_hash = substr($response, 26*2, 48);
	my $ret = unpack('H*', GenerateNTResponse(pack('H*',$authchallenge), pack('H*', $chap_peer_challenge), $uname, $passwd) );
	return $chap_ntv2_hash eq $ret;
}

sub chk_chap {
   my ($chap_password, $passwd, $chap_challenge) = @_;
   $chap_password =~ s/^0x//;
   $chap_challenge =~ s/^0x//;
   my $chap_id = substr($chap_password, 0, 2);
   $chap_password = substr($chap_password, 2);
   return $chap_password eq md5_hex(pack('H*',$chap_id).$passwd.pack('H*',$chap_challenge));
}

sub bin2hex ($) {
	my $bin = shift;
	print join('', unpack("H*",$bin))."\n";
}
}1;