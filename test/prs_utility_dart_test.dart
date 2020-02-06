import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/pointycastle.dart';

import 'package:prs_utility_dart/prs_utility_dart.dart';
import "package:pointycastle/key_derivators/pbkdf2.dart";
import 'package:prs_utility_dart/src/web3dart/crypto.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
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

  test('generate new keystore', () async {
    final keystore = await SignUtility.createKeystore('123123');
    final newKeystore =
        await SignUtility.generateNewKeystore(keystore, '123123', '234234');
    expect(newKeystore, isNotNull);
  });

  test('recover address', () async {
    final hash = SignUtility.keecak256String('hello prs');
    String signature = await SignUtility.signHash(hash,
        '6e204c62726a19fe3f43c4ca9739b7ffa37e4a3226f824f3e24e00a5890addc6');
    final address = SignUtility.recoverAddress(signature, hash);
    expect(address, '758ea2601697fbd3ba6eb6774ed70b6c4cdb0ef9');
  });

  setUpAll(() {
    MethodChannel channel =
        const MethodChannel('one.press.utility/prs_utility_plugin');
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      if (methodCall.method == 'pbkdf2') {
        final salt = methodCall.arguments['salt'] as String;
        final password = methodCall.arguments['password'] as String;
        final iterations = methodCall.arguments['iterations'] as int;
        final keyLength = methodCall.arguments['keyLength'] as int;
        final pbkdf2 = new PBKDF2KeyDerivator(new HMac(new SHA256Digest(), 64));
        pbkdf2.init(Pbkdf2Parameters(hexToBytes(salt), iterations, keyLength));
        return bytesToHex(pbkdf2.process(utf8.encode(password)));
      }
      return null;
    });
  });
}
