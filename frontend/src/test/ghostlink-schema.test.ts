import { describe, expect, it } from 'vitest';

import {
  createDefaultGhostLinkInboundSettings,
  createDefaultInboundSettings,
} from '@/lib/xray/inbound-defaults';
import { formValuesToWirePayload } from '@/lib/xray/inbound-form-adapter';
import { InboundFormSchema } from '@/schemas/forms/inbound-form';
import {
  GHOSTLINK_DEFAULT_LISTEN,
  GHOSTLINK_DEFAULT_PORT,
  generateGhostLinkNodeSecret,
  generateGhostLinkShortID,
  GhostLinkInboundSettingsSchema,
} from '@/schemas/protocols/inbound/ghostlink';

const settings = {
  version: 1 as const,
  transportPreset: 'h2' as const,
  identityTls: {
    serverName: 'www.speedtest.net',
    clientId: 'node-client',
    secret: 'ghostlink-node-identity-secret-32',
    publicKey: 'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw',
    privateKey: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA',
    shortId: '0011223344556677',
  },
  certificateFile: '/etc/ghostlink/fullchain.pem',
  privateKeyFile: '/etc/ghostlink/privkey.pem',
  serverName: 'edge.example.com',
  webBackendUrl: 'http://127.0.0.1:8081',
  clients: [],
};

describe('GhostLink inbound schema', () => {
  it('registers a dedicated protocol and settings factory', () => {
    expect(createDefaultInboundSettings('ghostlink')).toEqual(
      createDefaultGhostLinkInboundSettings(),
    );
    expect(createDefaultGhostLinkInboundSettings()).toMatchObject({
      transportPreset: 'h2',
      identityTls: {
        serverName: 'www.speedtest.net',
        clientId: 'node-client',
      },
      certificateFile: '',
      privateKeyFile: '',
    });
  });

  it('accepts required server paths and a loopback fallback origin', () => {
    expect(GhostLinkInboundSettingsSchema.parse(settings)).toEqual(settings);
  });

  it('rejects relative paths and non-loopback or path-bearing fallback URLs', () => {
    for (const invalid of [
      { ...settings, certificateFile: 'relative.pem' },
      { ...settings, privateKeyFile: '/etc/ghostlink/ key.pem ' },
      { ...settings, webBackendUrl: 'https://127.0.0.1:8081' },
      { ...settings, webBackendUrl: 'http://example.com:8081' },
      { ...settings, webBackendUrl: 'http://127.0.0.1:8081/admin' },
      { ...settings, webBackendUrl: 'http://127.0.0.1/admin' },
      { ...settings, webBackendUrl: 'http://127.0.0.1:0' },
    ]) {
      expect(GhostLinkInboundSettingsSchema.safeParse(invalid).success).toBe(false);
    }
  });

  it('maps all three presets and requires a complete identity credential set', () => {
    for (const preset of ['h2', 'h2-capsule', 'dual'] as const) {
      expect(
        GhostLinkInboundSettingsSchema.safeParse({ ...settings, transportPreset: preset }).success,
      ).toBe(true);
    }
    expect(
      GhostLinkInboundSettingsSchema.safeParse({
        ...settings,
        identityTls: { ...settings.identityTls, publicKey: '' },
      }).success,
    ).toBe(false);
    expect(
      GhostLinkInboundSettingsSchema.safeParse({
        ...settings,
        identityTls: { ...settings.identityTls, shortId: '0011' },
      }).success,
    ).toBe(false);
    expect(
      GhostLinkInboundSettingsSchema.safeParse({
        ...settings,
        transportPreset: 'dual',
        certificateFile: '',
      }).success,
    ).toBe(false);
  });

  it('generates a 32-byte node secret and an 8-byte short ID', () => {
    expect(generateGhostLinkNodeSecret()).toMatch(/^[0-9a-f]{64}$/);
    expect(generateGhostLinkShortID()).toMatch(/^[0-9a-f]{16}$/);
  });

  it('uses the product defaults requested by the preset form', () => {
    expect(GHOSTLINK_DEFAULT_PORT).toBe(28443);
    expect(GHOSTLINK_DEFAULT_LISTEN).toBe('0.0.0.0');
  });

  it('rejects delayed-start expiry and package auto-renew client modes', () => {
    const client = {
      id: 'client-01',
      email: 'ghost@example.test',
      secret: '0123456789abcdef0123456789abcdef',
      enable: true,
    };
    expect(
      GhostLinkInboundSettingsSchema.safeParse({
        ...settings,
        clients: [{ ...client, expiryTime: -86400000 }],
      }).success,
    ).toBe(false);
    expect(
      GhostLinkInboundSettingsSchema.safeParse({
        ...settings,
        clients: [{ ...client, resetMax: 1 }],
      }).success,
    ).toBe(false);
  });

  it('accepts optional targetAddress host:port and rejects invalid values', () => {
    for (const valid of ['', '127.0.0.1:8443', '[::1]:8443', 'localhost:8443']) {
      expect(
        GhostLinkInboundSettingsSchema.safeParse({
          ...settings,
          identityTls: { ...settings.identityTls, targetAddress: valid },
        }).success,
      ).toBe(true);
    }
    for (const invalid of [' 127.0.0.1:8443', '127.0.0.1', ':8443', '127.0.0.1:0', '127.0.0.1:70000']) {
      expect(
        GhostLinkInboundSettingsSchema.safeParse({
          ...settings,
          identityTls: { ...settings.identityTls, targetAddress: invalid },
        }).success,
      ).toBe(false);
    }
  });

  it('serializes no Xray stream or sniffing fields', () => {
    const parsed = InboundFormSchema.parse({
      ...settings,
      protocol: 'ghostlink',
      port: 443,
      listen: '0.0.0.0',
      settings,
    });
    const withStaleXrayFields = {
      ...parsed,
      streamSettings: { network: 'tcp', security: 'none' },
      sniffing: { enabled: true, destOverride: ['http', 'tls'] },
    } as typeof parsed;
    const payload = formValuesToWirePayload(withStaleXrayFields);
    expect(payload.streamSettings).toBe('');
    expect(payload.sniffing).toBe('');
    expect(JSON.parse(payload.settings)).toMatchObject(settings);
  });
});
