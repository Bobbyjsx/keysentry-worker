export const config = {
  apiHost: process.env.KEYSENTRY_API_URL || 'http://localhost:8001',
  atlasApiKey: process.env.ATLAS_API_KEY || '',
  encryptionKey: process.env.ENCRYPTION_KEY || '',
  internalSecret: process.env.INTERNAL_API_SECRET || '',
};
