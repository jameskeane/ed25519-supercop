declare module "@pulseapp/ed25519-supercop" {
  export function createSeed(): Buffer;
  export function createKeyPair(seed: Buffer): { publicKey: Buffer; secretKey: Buffer };
  export function sign(message: Buffer, publicKey: Buffer, secretKey: Buffer): Buffer;
  export function verify(signature: Buffer, message: Buffer, publicKey: Buffer): boolean;
}
