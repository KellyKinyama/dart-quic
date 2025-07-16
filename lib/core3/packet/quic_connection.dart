enum Status {
  Created,
  Handshaking,
  Connected,
  Closing,
  Draining,
  Closed,
  Failed;

  bool closingOrDraining() {
    return this == Closing ||
        this == Draining ||
        this == Closed ||
        this == Failed;
  }

  bool isClosing() {
    return this == Closing;
  }
}

enum DatagramExtensionStatus { Disabled, Enable, Enabled, EnabledReceiveOnly }

enum VersionNegotiationStatus {
  NotStarted,
  VersionChangeUnconfirmed,
  VersionNegotiated,
}

enum ErrorType { QUIC_LAYER_ERROR, APPLICATION_ERROR }
