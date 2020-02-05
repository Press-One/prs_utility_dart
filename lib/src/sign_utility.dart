import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:web3dart/crypto.dart';
import 'package:web3dart/web3dart.dart';
import 'dart:convert';

import 'dart:async';
import 'dart:math';
import 'async_utility.dart';

class SignUtility {
  static Future<String> revert(String keystore, String password) async {
    try {
      var wallet = Wallet.fromJson(keystore, password);
      return bytesToHex(wallet.privateKey.privateKey);
    } catch (err) {
      throw err;
    }
  }

  static String keecak256String(String str) {
    return bytesToHex(keccakUtf8(str));
  }

  static String keccak256Byte(List<int> data) {
    final result = bytesToHex(keccak256(data));
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
    return keecak256String(password + email);
  }

  static Future<String> createKeystore(String password) async {
    return await AsyncUtility.execute(_createNewAccount, [password]);
  }

  static Future<String> _createNewAccount(List<dynamic> parameters) async {
    try {
      final password = parameters[0] as String;
      var rng = new Random.secure();
      final credentials = EthPrivateKey.createRandom(rng);
      final wallet = Wallet.createNew(credentials, password, rng);
      final str = wallet.toJson();
      var keystore = json.decode(str);
      var ethAddress = await credentials.extractAddress();
      keystore['address'] = ethAddress.hexNo0x;
      return json.encode(keystore);
    } catch (err) {
      throw err;
    }
  }

  static Future<String> generateNewKeystore(
      String keystore, String oldPassword, String newPassword) async {
    return await AsyncUtility.execute(
        _generateNewKeystore, [keystore, oldPassword, newPassword]);
    // try {
    //   var rng = new Random.secure();
    //   final credentials = Wallet.fromJson(keystore, oldPassword).privateKey;
    //   final wallet = Wallet.createNew(credentials, newPassword, rng);
    //   final str = wallet.toJson();
    //   var newKeystore = json.decode(str);

    //   var ethAddress = await credentials.extractAddress();
    //   newKeystore['address'] = ethAddress.hexNo0x;
    //   return json.encode(newKeystore);
    // } catch (err) {
    //   throw err;
    // }
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
      throw err;
    }
  }

  static Future<dynamic> signHash(String hash, String privateKey) async {
    return await AsyncUtility.execute(_signHash, [hash, privateKey]);
  }

  static String _signHash(List<dynamic> parameters) {
    try {
      final hash = parameters[0] as String;
      final privateKey = parameters[1] as String;
      final privateKeyBytes = hexToBytes(privateKey);
      final bytes = hexToBytes(hash);
      final signature = sign(bytes, privateKeyBytes);
      var result = bytesToHex(intToBytes(signature.r)) +
          bytesToHex(intToBytes(signature.s)) +
          '0' +
          (signature.v - 27).toString();
      return result;
    } catch (err) {
      throw err;
    }
  }

  static String recoverAddress(String signature, String hash) {
    return recoverAddressFromSignature(signature, hash);
  }

  static final ECDomainParameters _params = ECCurve_secp256k1();

  static String recoverAddressFromSignature(String signature, String hash) {
    final n = _params.n;
    BigInt r = hexToInt(signature.substring(0, 64));
    BigInt s = hexToInt(signature.substring(64, 128));
    int recId = hexToInt(signature.substring(128)).toInt();

    final msg = hexToBytes(hash);

    final i = BigInt.from(recId ~/ 2);
    final x = r + (i * n);

    //Parameter q of curve
    final prime = BigInt.parse(
        'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
        radix: 16);
    if (x.compareTo(prime) >= 0) return null;

    final R = _decompressKey(x, (recId & 1) == 1, _params.curve);
    if (!(R * n).isInfinity) return null;

    final e = bytesToInt(msg);

    final eInv = (BigInt.zero - e) % n;
    final rInv = r.modInverse(n);
    final srInv = (rInv * s) % n;
    final eInvrInv = (rInv * eInv) % n;

    final q = (_params.G * eInvrInv) + (R * srInv);

    final bytes = q.getEncoded(false);

    final address = bytesToHex(publicKeyToAddress(bytes.sublist(1)));
    return address;
  }

  static ECPoint _decompressKey(BigInt xBN, bool yBit, ECCurve c) {
    List<int> x9IntegerToBytes(BigInt s, int qLength) {
      //https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/x9/X9IntegerConverter.java#L45
      final bytes = intToBytes(s);

      if (qLength < bytes.length) {
        return bytes.sublist(0, bytes.length - qLength);
      } else if (qLength > bytes.length) {
        final tmp = List<int>.filled(qLength, 0);

        final offset = qLength - bytes.length;
        for (var i = 0; i < bytes.length; i++) {
          tmp[i + offset] = bytes[i];
        }

        return tmp;
      }

      return bytes;
    }

    final compEnc = x9IntegerToBytes(xBN, 1 + ((c.fieldSize + 7) ~/ 8));
    compEnc[0] = yBit ? 0x03 : 0x02;
    return c.decodePoint(compEnc);
  }
}
