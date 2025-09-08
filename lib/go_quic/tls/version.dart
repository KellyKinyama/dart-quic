class ProtocolVersion {
  final int major;
  final int minor;

  ProtocolVersion(this.major, this.minor);

  @override
  String toString() => '$major.$minor';
}