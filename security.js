import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
export function encrypt(value) {
  if (value == null || value === '') return null;
  const key = Buffer.from(process.env.FIELD_ENCRYPTION_KEY || '', 'hex');
  if (key.length !== 32) throw new Error('FIELD_ENCRYPTION_KEY must be 32 bytes / 64 hex chars');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return `v1:${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted.toString('hex')}`;
}
export function decrypt(value) {
  if (!value) return null;
  const [version, ivHex, tagHex, dataHex] = value.split(':');
  if (version !== 'v1') throw new Error('Unsupported encrypted field version');
  const key = Buffer.from(process.env.FIELD_ENCRYPTION_KEY || '', 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
}
export function signToken(user) {
  return jwt.sign({ sub: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '8h', issuer: 'nursecare-pro' });
}
export function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try { req.user = jwt.verify(token, process.env.JWT_SECRET, { issuer: 'nursecare-pro' }); next(); }
  catch { res.status(401).json({ error: 'Authentication required' }); }
}
export const allow = (...roles) => (req,res,next) => roles.includes(req.user?.role) ? next() : res.status(403).json({error:'Insufficient permission'});
