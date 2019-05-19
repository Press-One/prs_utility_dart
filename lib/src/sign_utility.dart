import 'package:web3dart/web3dart.dart';
import 'package:web3dart/crypto.dart';
import 'package:pointycastle/digests/sha3.dart';
import 'dart:convert';

import 'dart:async';
import 'dart:math';
import 'async_utility.dart';

class SignUtility {
  static Future<String> revert(String keystore, String password) async {
    return await AsyncUtility.execute(_revert, [keystore, password]);
  }

  static String _revert(List<dynamic> parameters) {
    final keystore = parameters[0] as String;
    final password = parameters[1] as String;
    var wallet = Wallet.fromJson(keystore, password);
    return bytesToHex(wallet.privateKey.privateKey);
  }

  static String keecak256String(String str) {
    final bytes = utf8.encode(str);
    return keccak256Byte(bytes);
  }

  static String keccak256Byte(List<int> data) {
    final int _shaBytes = 256 ~/ 8;
    final SHA3Digest sha3digest = SHA3Digest(_shaBytes * 8);
    final result = bytesToHex(sha3digest.process(data));
    return result;
  }

  static String calcRequestHash(String path, Map<String, dynamic> payload) {
    final prefix = sortedToQueryString({'path': path});
    final sortedPayload = sortedToQueryString(payload);
    var result = "$prefix";
    if (sortedPayload != null) {
      result = result + '&' + sortedPayload;
    }
    return keecak256String(result);
  }

  static String calcObjectHash(Map<String, dynamic> object) {
    final sortedPayload = sortedToQueryString(object);
    return keecak256String(sortedPayload);
  }

  static String sortedToQueryString(Map<String, dynamic> message) {
    if (message == null) {
      return null;
    }
    var sortedKeys = message.keys.toList()..sort();
    var result = sortedKeys.map((key) {
      return "$key=${Uri.encodeComponent(message[key].toString())}";
    }).toList();
    return result.join('&');
  }

  static String hashPassword(email, password) {
    final bytes = utf8.encode(password + email);
    return keccak256Byte(bytes);
  }

  static Future<String> createKeystore(String password) async {
    return await AsyncUtility.execute(_createNewAccount, [password]);
  }

  static Future<String> _createNewAccount(List<dynamic> parameters) async {
    final password = parameters[0] as String;
    var rng = new Random.secure();
    final credentials = EthPrivateKey.createRandom(rng);
    final wallet = Wallet.createNew(credentials, password, rng);
    final str = wallet.toJson();
    var keystore = json.decode(str);
    var ethAddress = await credentials.extractAddress();
    keystore['address'] = ethAddress.hexNo0x;
    return json.encode(keystore);
  }

  static Future<String> generateNewKeystore(
      String keystore, String oldPassword, String newPassword) async {
    return await AsyncUtility.execute(
        _generateNewKeystore, [keystore, oldPassword, newPassword]);
  }

  static Future<String> _generateNewKeystore(List<dynamic> parameters) async {
    final keystore = parameters[0] as String;
    final oldPassword = parameters[1] as String;
    final newPassword = parameters[2] as String;

    try {
      var rng = new Random.secure();
      final credentials = Wallet.fromJson(keystore, oldPassword).privateKey;
      final wallet = Wallet.createNew(credentials, newPassword, rng);
      final str = wallet.toJson();
      var newKeystore = json.decode(str);

      var ethAddress = await credentials.extractAddress();
      newKeystore['address'] = ethAddress.hexNo0x;
      return json.encode(newKeystore);
    } catch (err) {
      return null;
    }
  }

  static Future<dynamic> signHash(String hash, String privateKey) async {
    return await AsyncUtility.execute(_signHash, [hash, privateKey]);
  }

  static String _signHash(List<dynamic> parameters) {
    final hash = parameters[0] as String;
    final privateKey = parameters[1] as String;
    final privateKeyBytes = hexToBytes(privateKey);
    final bytes = hexToBytes(hash);
    final signature = sign(bytes, privateKeyBytes);
    var result = bytesToHex(intToBytes(signature.r)) +
        bytesToHex(intToBytes(signature.s)) +
        (signature.v - 27).toString();
    return result;
  }
}
