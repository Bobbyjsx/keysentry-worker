import crypto from 'node:crypto';
import fernet from 'fernet';

export class EncryptionService {
  private secret: fernet.Secret;

  constructor(base64Key: string) {
    if (!base64Key) {
      throw new Error('Encryption key is required');
    }

    // Mirror Python logic: if key is not valid length (43 or 44), derive one via SHA256
    let validKey = base64Key;
    if (validKey.length !== 43 && validKey.length !== 44) {
      const hash = crypto.createHash('sha256').update(base64Key).digest();
      validKey = hash
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    }

    this.secret = new fernet.Secret(validKey);
  }

  decrypt(encryptedToken: string): string {
    const token = new fernet.Token({
      secret: this.secret,
      token: encryptedToken,
      ttl: 0, // never expire
    });
    const decoded = token.decode();
    if (!decoded) {
      throw new Error('Failed to decrypt token');
    }
    return decoded;
  }
}
