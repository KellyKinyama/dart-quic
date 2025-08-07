enum QuicProtocolVersion {
  NEGOTIATION(0),
  VERSION_1(0x00000001),
  VERSION_2(0x6B3343CF);

  final int value;
  const QuicProtocolVersion(this.value);
}

enum CipherSuite {
  AES_128_GCM_SHA256(0x1301),
  AES_256_GCM_SHA384(0x1302),
  CHACHA20_POLY1305_SHA256(0x1303),
  EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF);

  final int value;
  const CipherSuite(this.value);
}
