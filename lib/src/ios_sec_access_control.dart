class IosSecAccessControl {
  const IosSecAccessControl._(this.index);

  final int index;

  static const IosSecAccessControl kSecAccessControlApplicationPassword = const IosSecAccessControl._(0);

  static const IosSecAccessControl kSecAccessControlPrivateKeyUsage = const IosSecAccessControl._(1);

  static const IosSecAccessControl kSecAccessControlDevicePasscode = const IosSecAccessControl._(2);

  @deprecated
  static const IosSecAccessControl kSecAccessControlTouchIDAny = const IosSecAccessControl._(3);

  static const IosSecAccessControl kSecAccessControlBiometryAny = const IosSecAccessControl._(4);

  @deprecated
  static const IosSecAccessControl kSecAccessControlTouchIDCurrentSet = const IosSecAccessControl._(5);

  static const IosSecAccessControl kSecAccessControlBiometryCurrentSet = const IosSecAccessControl._(6);

  static const IosSecAccessControl kSecAccessControlUserPresence = const IosSecAccessControl._(7);

  static const List<IosSecAccessControl> values = const <IosSecAccessControl>[
    kSecAccessControlApplicationPassword,
    kSecAccessControlPrivateKeyUsage,
    kSecAccessControlDevicePasscode,
    kSecAccessControlTouchIDAny,
    kSecAccessControlBiometryAny,
    kSecAccessControlTouchIDCurrentSet,
    kSecAccessControlBiometryCurrentSet,
    kSecAccessControlUserPresence
  ];

  @override
  String toString() {
    return const <int, String>{
      0: 'kSecAccessControlApplicationPassword',
      1: 'kSecAccessControlPrivateKeyUsage',
      2: 'kSecAccessControlDevicePasscode',
      3: 'kSecAccessControlTouchIDAny',
      4: 'kSecAccessControlBiometryAny',
      5: 'kSecAccessControlTouchIDCurrentSet',
      6: 'kSecAccessControlBiometryCurrentSet',
      7: 'kSecAccessControlUserPresence'
    }[index];
  }
}
