import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'ios_sec_access_control.dart';

class SensitiveInfo {
  static const MethodChannel channel = const MethodChannel('io.qwil/sensitive_info');

  static const String keychainName = 'app';

  static Future<bool> get isSensorAvailable async {
    final String result = await channel.invokeMethod('isSensorAvailable');
    return result != 'none';
  }

  static Future<String> get availableSensor async {
    return await channel.invokeMethod('isSensorAvailable');
  }

  static Future<String> getItem(
      {@required String key,
      @required String kSecUseOperationPrompt,
      bool biometric = true,
      String keychainName = keychainName}) async {
    assert(key != null && key.isNotEmpty);
    assert(kSecUseOperationPrompt != null && kSecUseOperationPrompt.isNotEmpty);

    return await channel.invokeMethod('getItem', <String, dynamic>{
      'key': key,
      'biometric': biometric,
      'keychainName': keychainName,
      'kSecUseOperationPrompt': kSecUseOperationPrompt
    });
  }

  static Future<String> setItem(
      {@required String key,
      @required String value,
      bool biometric = true,
      String keychainName = keychainName,
      IosSecAccessControl secAccessControl = IosSecAccessControl.kSecAccessControlBiometryAny,
      String secAttrAccessible}) async {
    assert(key != null && key.isNotEmpty);
    assert(value != null && value.isNotEmpty);

    return await channel.invokeMethod('setItem', <String, dynamic>{
      'key': key,
      'value': value,
      'biometric': biometric,
      'keychainName': keychainName,
      'kSecAccessControl': secAccessControl.toString(),
      'kSecAttrAccessible': secAttrAccessible
    });
  }

  static Future<Null> deleteItem({@required String key, String keychainName = keychainName}) async {
    assert(key != null && key.isNotEmpty);
    return await channel.invokeMethod('deleteItem', <String, dynamic>{'key': key, 'keychainName': keychainName});
  }

  static Future<Map<String, dynamic>> getAllItems({String keychainNam = keychainName}) async {
    final Map<dynamic, dynamic> result =
        await channel.invokeMethod('getAllItems', <String, dynamic>{'keychainName': keychainName});

    return result.cast<String, dynamic>();
  }

  static Future<String> get cancelFingerprintAuth async => await channel.invokeMethod('cancelFingerprintAuth');
}
