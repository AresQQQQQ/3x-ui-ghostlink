import { z } from 'zod';

const GHOSTLINK_SECRET_MIN_BYTES = 32;
const GHOSTLINK_SECRET_MAX_BYTES = 1024;
export const GHOSTLINK_DEFAULT_PORT = 28443;
export const GHOSTLINK_DEFAULT_LISTEN = '0.0.0.0';
export const GHOSTLINK_TRANSPORT_PRESETS = ['h2', 'h2-capsule', 'dual'] as const;
export type GhostLinkTransportPreset = (typeof GHOSTLINK_TRANSPORT_PRESETS)[number];

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

function isAbsoluteServerPath(value: string): boolean {
  return value.startsWith('/') && value.trim() === value && value.length > 1;
}

function isLoopbackIP(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (host === '::1') return true;
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return !!match && match.slice(1).every((part) => Number(part) <= 255);
}

function isIdentityHostname(value: string): boolean {
  return (
    value.length > 0 && value.length <= 253 && value.trim() === value && !/[:/\\\s]/.test(value)
  );
}

function isIdentityTargetAddress(value: string): boolean {
  if (value === '') return true;
  if (value.trim() !== value || /\s/.test(value)) return false;
  let host = '';
  let portText = '';
  if (value.startsWith('[')) {
    const end = value.indexOf(']:');
    if (end <= 1) return false;
    host = value.slice(1, end);
    portText = value.slice(end + 2);
  } else {
    const colon = value.lastIndexOf(':');
    if (colon <= 0 || value.indexOf(':') !== colon) return false;
    host = value.slice(0, colon);
    portText = value.slice(colon + 1);
  }
  if (!host || !/^\d+$/.test(portText)) return false;
  const port = Number(portText);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function isNodeClientID(value: string): boolean {
  if (value.length < 1 || value.length > 128 || value.trim() !== value) return false;
  return Array.from(value).every((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code >= 0x21 && code <= 0x7e && char !== ':';
  });
}

function isBase64URLKey(value: string): boolean {
  return value.length === 43 && /^[A-Za-z0-9_-]+$/.test(value);
}

export function generateGhostLinkNodeSecret(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

export function generateGhostLinkShortID(): string {
  const bytes = new Uint8Array(8);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

export const GhostLinkIdentityTLSSchema = z.object({
  serverName: z
    .string()
    .refine(isIdentityHostname, 'pages.inbounds.form.ghostlink.targetSniInvalid'),
  targetAddress: z
    .string()
    .refine(isIdentityTargetAddress, 'pages.inbounds.form.ghostlink.targetAddressInvalid')
    .optional(),
  clientId: z
    .string()
    .refine(isNodeClientID, 'pages.inbounds.form.ghostlink.identityClientIdInvalid'),
  secret: z
    .string()
    .refine(
      (value) =>
        utf8ByteLength(value) >= GHOSTLINK_SECRET_MIN_BYTES &&
        utf8ByteLength(value) <= GHOSTLINK_SECRET_MAX_BYTES,
      'pages.inbounds.form.ghostlink.identitySecretInvalid',
    ),
  publicKey: z.string().refine(isBase64URLKey, 'pages.inbounds.form.ghostlink.identityKeyInvalid'),
  privateKey: z.string().refine(isBase64URLKey, 'pages.inbounds.form.ghostlink.identityKeyInvalid'),
  shortId: z.string().regex(/^[0-9a-fA-F]{16}$/, 'pages.inbounds.form.ghostlink.shortIdInvalid'),
});

export function isLoopbackHTTPOrigin(value: string): boolean {
  if (value.trim() === '') return true;
  if (value.trim() !== value) return false;
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'http:' ||
      url.username !== '' ||
      url.password !== '' ||
      url.search !== '' ||
      url.hash !== '' ||
      (url.pathname !== '' && url.pathname !== '/') ||
      url.port === ''
    ) {
      return false;
    }
    const port = Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
    return isLoopbackIP(url.hostname);
  } catch {
    return false;
  }
}

export const GhostLinkClientSchema = z
  .object({
    id: z
      .string()
      .min(1)
      .max(128)
      .refine(
        (value) =>
          value.trim() === value &&
          Array.from(value).every((char) => {
            const code = char.codePointAt(0) ?? 0;
            return code >= 0x21 && code <= 0x7e && char !== ':';
          }),
        'pages.clients.ghostLink.invalidClientId',
      ),
    email: z.string().min(1),
    secret: z
      .string()
      .refine(
        (value) =>
          utf8ByteLength(value) >= GHOSTLINK_SECRET_MIN_BYTES &&
          utf8ByteLength(value) <= GHOSTLINK_SECRET_MAX_BYTES,
        'pages.clients.ghostLink.invalidSecret',
      ),
    totalGB: z.number().int().min(0).default(0),
    expiryTime: z.number().int().min(0).default(0),
    enable: z.boolean().default(true),
    reset: z.number().int().default(0),
    resetDay: z.number().int().default(0),
    resetWeekday: z.number().int().default(0),
    resetMax: z.number().int().default(0),
    trafficReset: z.enum(['never', 'hourly', 'daily', 'weekly', 'monthly']).default('never'),
    trafficResetDay: z.number().int().min(0).max(31).default(1),
  })
  .loose()
  .superRefine((client, ctx) => {
    if (client.reset || client.resetDay || client.resetWeekday || client.resetMax) {
      ctx.addIssue({
        code: 'custom',
        message: 'pages.clients.ghostLink.autoRenewUnsupported',
        path: ['reset'],
      });
    }
  });

export const GhostLinkInboundSettingsSchema = z
  .object({
    version: z.literal(1).default(1),
    transportPreset: z.enum(GHOSTLINK_TRANSPORT_PRESETS).optional(),
    identityTls: GhostLinkIdentityTLSSchema.optional(),
    certificateFile: z.string().default(''),
    privateKeyFile: z.string().default(''),
    serverName: z
      .string()
      .default('')
      .refine(
        (value) => value.trim() === value,
        'pages.inbounds.form.ghostlink.serverNameWhitespace',
      ),
    webBackendUrl: z
      .string()
      .default('')
      .refine(isLoopbackHTTPOrigin, 'pages.inbounds.form.ghostlink.webBackendUrlInvalid'),
    clients: z.array(GhostLinkClientSchema).default([]),
  })
  .superRefine((settings, ctx) => {
    if (settings.transportPreset && !settings.identityTls) {
      ctx.addIssue({
        code: 'custom',
        message: 'pages.inbounds.form.ghostlink.identityRequired',
        path: ['identityTls'],
      });
    }
    const needsCertificate = settings.transportPreset === 'dual' || !settings.transportPreset;
    for (const field of ['certificateFile', 'privateKeyFile'] as const) {
      const value = settings[field];
      if (needsCertificate && !isAbsoluteServerPath(value)) {
        ctx.addIssue({
          code: 'custom',
          message: 'pages.inbounds.form.ghostlink.absolutePathRequired',
          path: [field],
        });
      } else if (value !== '' && !isAbsoluteServerPath(value)) {
        ctx.addIssue({
          code: 'custom',
          message: 'pages.inbounds.form.ghostlink.absolutePathRequired',
          path: [field],
        });
      }
    }
  });

export type GhostLinkClient = z.infer<typeof GhostLinkClientSchema>;
export type GhostLinkIdentityTLS = z.infer<typeof GhostLinkIdentityTLSSchema>;
export type GhostLinkInboundSettings = z.infer<typeof GhostLinkInboundSettingsSchema>;
