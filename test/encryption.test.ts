import crypto from 'crypto';
import fernet from 'fernet';
import { describe, expect, it } from 'vitest';
import { EncryptionService } from '@/core/encryption';

describe('EncryptionService', () => {
  const testKey = 'G5matvyobpiTtIzNpVigxF+hvHtMFEM9mJkLzKnc'; // 32-byte base64url encoded
  const testMessage = 'ghp_super_secret_github_token';

  it('should decrypt a fernet token properly', () => {
    // Encrypt something to test
    const hash = crypto.createHash('sha256').update(testKey).digest();
    const validKey = hash
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    const secret = new fernet.Secret(validKey);
    const token = new fernet.Token({
      iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      secret: secret,
      time: Date.parse(new Date().toUTCString()),
    });

    const encoded = token.encode(testMessage);

    const service = new EncryptionService(testKey);
    const decrypted = service.decrypt(encoded);

    expect(decrypted).toBe(testMessage);
  });

  it('should throw error if key is missing', () => {
    expect(() => new EncryptionService('')).toThrowError(
      'Encryption key is required'
    );
  });
});
