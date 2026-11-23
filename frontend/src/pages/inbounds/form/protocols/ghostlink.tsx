import { useState } from 'react';
import { useFormContext, useWatch } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Form, Input, Select, Space, message } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

import { FormField } from '@/components/form/rhf';
import {
  generateGhostLinkNodeSecret,
  generateGhostLinkShortID,
  type GhostLinkTransportPreset,
} from '@/schemas/protocols/inbound/ghostlink';
import { HttpUtil } from '@/utils';

const PRESET_OPTIONS: { value: GhostLinkTransportPreset; labelKey: string }[] = [
  { value: 'h2', labelKey: 'pages.inbounds.form.ghostlink.presetH2' },
  { value: 'h2-capsule', labelKey: 'pages.inbounds.form.ghostlink.presetH2Capsule' },
  { value: 'dual', labelKey: 'pages.inbounds.form.ghostlink.presetDual' },
];

export default function GhostLinkFields() {
  const { t } = useTranslation();
  const [messageApi, messageContextHolder] = message.useMessage();
  const { control, setValue } = useFormContext();
  const [generatingKeypair, setGeneratingKeypair] = useState(false);
  const preset = (useWatch({ control, name: 'settings.transportPreset' }) ??
    'h2') as GhostLinkTransportPreset;

  const generateKeypair = async () => {
    setGeneratingKeypair(true);
    try {
      const msg = await HttpUtil.get('/panel/api/server/getNewX25519Cert');
      if (msg?.success) {
        const keys = msg.obj as { privateKey: string; publicKey: string };
        setValue('settings.identityTls.privateKey', keys.privateKey, { shouldDirty: true });
        setValue('settings.identityTls.publicKey', keys.publicKey, { shouldDirty: true });
      }
    } catch {
      messageApi.error(t('pages.inbounds.form.ghostlink.generateFailed'));
    } finally {
      setGeneratingKeypair(false);
    }
  };

  const presetDescriptionKey =
    preset === 'h2-capsule'
      ? 'pages.inbounds.form.ghostlink.presetH2CapsuleHint'
      : preset === 'dual'
        ? 'pages.inbounds.form.ghostlink.presetDualHint'
        : 'pages.inbounds.form.ghostlink.presetH2Hint';

  return (
    <>
      {messageContextHolder}
      <Alert
        type="info"
        showIcon
        title={t('pages.inbounds.form.ghostlink.notXray')}
        description={t('pages.inbounds.form.ghostlink.presetHint')}
      />
      <FormField
        name={['settings', 'transportPreset']}
        label={t('pages.inbounds.form.ghostlink.transportPreset')}
        required
      >
        <Select
          options={PRESET_OPTIONS.map(({ value, labelKey }) => ({
            value,
            label: t(labelKey),
          }))}
        />
      </FormField>
      <Alert
        className="mb-12"
        type={preset === 'dual' ? 'warning' : 'success'}
        showIcon
        title={t(presetDescriptionKey)}
      />

      <FormField
        name={['settings', 'identityTls', 'serverName']}
        label={t('pages.inbounds.form.ghostlink.targetSni')}
        tooltip={t('pages.inbounds.form.ghostlink.targetSniHint')}
        required
      >
        <Input placeholder="www.speedtest.net" />
      </FormField>

      <FormField
        name={['settings', 'identityTls', 'targetAddress']}
        label={t('pages.inbounds.form.ghostlink.targetAddress')}
        tooltip={t('pages.inbounds.form.ghostlink.targetAddressHint')}
      >
        <Input placeholder="127.0.0.1:8443" />
      </FormField>

      <FormField
        name={['settings', 'identityTls', 'clientId']}
        label={t('pages.inbounds.form.ghostlink.identityClientId')}
        tooltip={t('pages.inbounds.form.ghostlink.identityClientIdHint')}
        required
      >
        <Input placeholder="node-client" />
      </FormField>

      <Form.Item
        label={t('pages.inbounds.form.ghostlink.x25519Keypair')}
        tooltip={t('pages.inbounds.form.ghostlink.x25519Hint')}
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space.Compact block>
            <FormField name={['settings', 'identityTls', 'privateKey']} noStyle>
              <Input.Password
                aria-label={t('pages.inbounds.form.ghostlink.privateKey')}
                placeholder={t('pages.inbounds.form.ghostlink.privateKey')}
              />
            </FormField>
            <Button
              icon={<ReloadOutlined aria-hidden />}
              loading={generatingKeypair}
              onClick={() => void generateKeypair()}
            >
              {t('pages.inbounds.form.ghostlink.generate')}
            </Button>
          </Space.Compact>
          <FormField name={['settings', 'identityTls', 'publicKey']} noStyle>
            <Input
              aria-label={t('pages.inbounds.form.ghostlink.publicKey')}
              placeholder={t('pages.inbounds.form.ghostlink.publicKey')}
            />
          </FormField>
        </Space>
      </Form.Item>

      <Form.Item label={t('pages.inbounds.form.ghostlink.nodeSecret')}>
        <Space.Compact block>
          <FormField name={['settings', 'identityTls', 'secret']} noStyle>
            <Input.Password
              aria-label={t('pages.inbounds.form.ghostlink.nodeSecret')}
              placeholder={t('pages.inbounds.form.ghostlink.nodeSecret')}
            />
          </FormField>
          <Button
            icon={<ReloadOutlined aria-hidden />}
            onClick={() =>
              setValue('settings.identityTls.secret', generateGhostLinkNodeSecret(), {
                shouldDirty: true,
              })
            }
          >
            {t('pages.inbounds.form.ghostlink.generate')}
          </Button>
        </Space.Compact>
      </Form.Item>

      <Form.Item label={t('pages.inbounds.form.ghostlink.shortId')}>
        <Space.Compact block>
          <FormField name={['settings', 'identityTls', 'shortId']} noStyle>
            <Input
              aria-label={t('pages.inbounds.form.ghostlink.shortId')}
              placeholder="0011223344556677"
            />
          </FormField>
          <Button
            icon={<ReloadOutlined aria-hidden />}
            onClick={() =>
              setValue('settings.identityTls.shortId', generateGhostLinkShortID(), {
                shouldDirty: true,
              })
            }
          >
            {t('pages.inbounds.form.ghostlink.generate')}
          </Button>
        </Space.Compact>
      </Form.Item>

      {preset === 'dual' && (
        <>
          <Alert
            className="mb-12"
            type="warning"
            showIcon
            title={t('pages.inbounds.form.ghostlink.dualCertificateHint')}
          />
          <FormField
            name={['settings', 'certificateFile']}
            label={t('pages.inbounds.form.ghostlink.certificateFile')}
            tooltip={t('pages.inbounds.form.ghostlink.absolutePathHint')}
            required
          >
            <Input placeholder="/etc/ghostlink/fullchain.pem" />
          </FormField>
          <FormField
            name={['settings', 'privateKeyFile']}
            label={t('pages.inbounds.form.ghostlink.privateKeyFile')}
            tooltip={t('pages.inbounds.form.ghostlink.absolutePathHint')}
            required
          >
            <Input.Password placeholder="/etc/ghostlink/privkey.pem" />
          </FormField>
        </>
      )}
    </>
  );
}
