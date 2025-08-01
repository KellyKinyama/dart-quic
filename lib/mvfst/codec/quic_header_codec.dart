// Let's assume you have a PacketHeader class defined
class PacketHeader {
  // ... properties of a packet header
}

class ParsedHeaderResult {
  bool isVersionNegotiation;
  PacketHeader? parsedHeader; // This is the nullable type

  ParsedHeaderResult(this.isVersionNegotiation, this.parsedHeader);
}

// And a function that would parse the header
ParsedHeaderResult parseHeader(dynamic data) {
  // In your C++ example, the function returns an Expected,
  // which handles errors. In Dart, you would typically handle
  // this with a try-catch block or a result class.
  
  // Example logic:
  bool isNegotiationPacket = data is VersionNegotiationPacket;
  if (isNegotiationPacket) {
    // If it's a negotiation packet, the header is absent.
    return ParsedHeaderResult(true, null); 
  } else {
    // If a header is successfully parsed, you return a valid object.
    PacketHeader header = PacketHeader(/* ... */);
    return ParsedHeaderResult(false, header);
  }
}