import 'package:flutter_test/flutter_test.dart';

import 'package:prs_utility_dart/prs_utility_dart.dart';

void main() {
  test('recover', () async {
    final privateKey = await SignUtility.revert(
        '{"address":"758ea2601697fbd3ba6eb6774ed70b6c4cdb0ef9","crypto":{"cipher":"aes-128-ctr","ciphertext":"92af6f6710eba271eae5ac7fec72c70d9f49215e7880a0c45d4c53e56bd7ea59","cipherparams":{"iv":"13ddf95d970e924c97e4dcd29ba96520"},"mac":"b9d81d78f067334ee922fb2863e32c14cbc46e479eeb0acc11fb31e39256004e","kdf":"pbkdf2","kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"79f90bb603491573e40a79fe356b88d0c7869852e43c2bbaabed44578a82bbfa"}},"id":"93028e51-a2a4-4514-bc1a-94b089445f35","version":3}',
        '123123');
    expect(privateKey,
        '6e204c62726a19fe3f43c4ca9739b7ffa37e4a3226f824f3e24e00a5890addc6');
  }, timeout: Timeout(const Duration(seconds: 300)));

  test('keccak256', () async {
    final hash = SignUtility.keecak256String('hello prs');
    expect(hash,
        '647df39ad889e83cc0b9b65375672d1bfe282565c564d3d553a435bf80e67d92');
  });

  test('hash password', () async {
    final hash = SignUtility.hashPassword('account@press.one', '123123');
    expect(hash,
        '2b16369e3a3a2b44bdef9d197b14b5448ebe960a5a2ddd57be434d983707aafd');
  });

  test('create account', () async {
    final keystore = await SignUtility.createKeystore('123123');
    expect(keystore, isNotNull);
  });

  test('recover address', () async {
    final hash = SignUtility.keecak256String('hello prs');
    String signature = await SignUtility.signHash(hash,
        '6e204c62726a19fe3f43c4ca9739b7ffa37e4a3226f824f3e24e00a5890addc6');
    final address = SignUtility.recoverAddress(signature, hash);
    expect(address, '758ea2601697fbd3ba6eb6774ed70b6c4cdb0ef9');
  });

  test('recover address', () async {
    final address1 = SignUtility.recoverAddress(
        '9cb66fa967e970129569e8b164785edf183e76a4d3cdffecf1f918a1fa7835cefe54b3d118d1755e5a051cd3a6df4f1ea016ebe20ab7eb8bf57a9d8ee9d1962e1',
        '565b63ac79b7d35a05322975340ae243e35ce084ae285c719fa6b203916f2845');
    final address2 = SignUtility.recoverAddress(
        '9cb66fa967e970129569e8b164785edf183e76a4d3cdffecf1f918a1fa7835ce01ab4c2ee72e8aa1a5fae32c5920b0e01a97f104a490b4afca57c0fde664ab1300',
        '565b63ac79b7d35a05322975340ae243e35ce084ae285c719fa6b203916f2845');

    expect(address1, address2);
  });

  test('sign', () async {
    final signature = await SignUtility.signHash(
        'a70b44e0a41bc225914180dc0785fd71f8f018d90e76e3c5687e027ad273b695',
        '6e204c62726a19fe3f43c4ca9739b7ffa37e4a3226f824f3e24e00a5890addc6');

    expect(signature,
        '47e4f89120b4b50518ca5c1ffe6d4ff9a364053dbd832cc13afd286130be561f6a1f241605b58176716c3572822eab7f5e4fd20527da2854367bf57ab46a5eec01');
  });
}
