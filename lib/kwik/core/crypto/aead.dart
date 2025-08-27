import 'dart:typed_data';

abstract class Aead {
  void computeKeys(Uint8List trafficSecret);

  Uint8List createHeaderProtectionMask(Uint8List sample);

  Uint8List getWriteIV();

  Uint8List aeadEncrypt(
    Uint8List associatedData,
    Uint8List message,
    Uint8List nonce,
  );

  Uint8List aeadDecrypt(
    Uint8List associatedData,
    Uint8List message,
    Uint8List nonce,
  );
  // throws DecryptionException;

  /**
     * Check whether the key phase carried by a received packet still matches the current key phase; if not, compute
     * new keys (to be used for decryption). Note that the changed key phase can also be caused by packet corruption,
     * so it is not yet sure whether a key update is really in progress (this will be sure when decryption of the packet
     * failed or succeeded).
     * @param keyPhaseBit
     */
  void checkKeyPhase(
    int keyPhaseBit, //short
  );

  /**
     * Compute new keys. Note that depending on the role of this Keys object, computing new keys concerns updating
     * the write secrets (role that initiates the key update) or the read secrets (role that responds to the key update).
     * @param selfInitiated        true when this role initiated the key update, so updating write secrets.
     */
  void computeKeyUpdate(bool selfInitiated);

  /**
     * Confirm that, if a key update was in progress, it has been successful and thus the new keys can (and should) be
     * used for decrypting all incoming packets.
     */
  void confirmKeyUpdateIfInProgress();

  /**
     * Confirm that, if a key update was in progress, it has been unsuccessful and thus the new keys should not be
     * used for decrypting all incoming packets.
     */
  void cancelKeyUpdateIfInProgress();

  int getKeyPhase(); //short

  int getKeyUpdateCounter();

  void setPeerAead(Aead peerAead);

  Uint8List getTrafficSecret();
}
