enum CipherSuiteId {
  TLS_NULL_WITH_NULL_NULL(0x0000),
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b),
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xc02f),
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xc009),
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xc013),
  Unsupported(0x0000);

  const CipherSuiteId(this.value);
  final int value;

  factory CipherSuiteId.fromInt(int val) {
    return values.firstWhere((e) => e.value == val,
        orElse: () => CipherSuiteId.Unsupported);
  }

  @override
  String toString() {
    switch (this) {
      case TLS_NULL_WITH_NULL_NULL:
        return "TLS_NULL_WITH_NULL_NULL";
      case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
      case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
      case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
      case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
      default:
        return "Unsupported";
    }
  }
}
enum ExtensionTypeValue {
  ServerName(0),
  SupportedEllipticCurves(10),
  SupportedPointFormats(11),
  SupportedSignatureAlgorithms(13),
  UseSrtp(14),
  UseExtendedMasterSecret(23),
  RenegotiationInfo(65281),
  Unsupported(9999);

  const ExtensionTypeValue(this.value);
  final int value;

  factory ExtensionTypeValue.fromInt(int key) {
    return values.firstWhere((element) => element.value == key,
        orElse: () => ExtensionTypeValue.Unsupported);
  }
}
