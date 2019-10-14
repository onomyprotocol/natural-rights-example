import { NRKeyPair } from '@natural-rights/client'

async function cryptKeyGen(): Promise<NRKeyPair> {
  const key = Math.floor(Math.random() * 16777215).toString(16)
  return {
    privKey: `cryptPrivKey-${key}`,
    pubKey: `cryptPubKey-${key}`
  }
}
async function signKeyGen(): Promise<NRKeyPair> {
  const key = Math.floor(Math.random() * 16777215).toString(16)
  return {
    privKey: `cryptPrivKey-${key}`,
    pubKey: `cryptPubKey-${key}`
  }
}

async function cryptTransformKeyGen(
  fromKeyPair: NRKeyPair,
  toPubKey: string
): Promise<string> {
  return `cryptTransform:${fromKeyPair.privKey}:${toPubKey}`
}

async function encrypt(pubKey: string, plaintext: string): Promise<string> {
  return `encrypted:${pubKey}:${plaintext}`
}

async function decrypt(
  keyPair: NRKeyPair,
  ciphertext: string
): Promise<string> {
  return ciphertext.replace(`encrypted:${keyPair.pubKey}:`, '')
}

async function cryptTransform(
  transformKey: string,
  ciphertext: string
): Promise<string> {
  const [, , plaintext] = ciphertext.split(':')
  const [, , pubKey] = transformKey.split(':')
  return encrypt(pubKey, plaintext) // NOTE: real primitive SHOULD NOT DECRYPT
}

async function sign(keyPair: NRKeyPair, text: string): Promise<string> {
  return `signature:${keyPair.pubKey}:${text}`
}

async function verify(
  pubKey: string,
  signature: string,
  text: string
): Promise<boolean> {
  return signature.replace(`signature:${pubKey}:`, '') === text
}

export const Primitives = {
  cryptKeyGen,
  cryptTransform,
  cryptTransformKeyGen,
  decrypt,
  encrypt,
  sign,
  signKeyGen,
  verify
}
