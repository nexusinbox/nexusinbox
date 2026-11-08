// Create an agent whose keys this browser holds: generate the signing and
// receiving key pairs here, register the public halves, and keep the
// private halves in this browser's keystore. Used by the first-run guide
// and the settings page.

import type { CreateAgentRequest, CreateAgentResponse } from "../api/types";
import {
  generateX25519KeyPairMaterial,
  saveRecipientPrivateKey,
} from "../crypto/recipient-keyring";
import {
  generateEd25519SigningKeyPairMaterial,
  saveSigningPrivateKey,
} from "../crypto/signing-keyring";

export async function createAgentWithLocalKeys(
  label: string,
  register: (payload: CreateAgentRequest) => Promise<CreateAgentResponse>,
): Promise<CreateAgentResponse> {
  const signingKeyPair = await generateEd25519SigningKeyPairMaterial();
  const encryptionKeyPair = await generateX25519KeyPairMaterial();
  const created = await register({
    label,
    public_key: signingKeyPair.publicKey,
    encryption_key: encryptionKeyPair.publicKey,
  });
  saveSigningPrivateKey(created.did, signingKeyPair.privateKey);
  saveRecipientPrivateKey(created.did, encryptionKeyPair.privateKey);
  return created;
}
