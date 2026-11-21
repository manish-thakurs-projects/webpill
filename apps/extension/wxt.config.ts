import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'webpill',
    description: 'A private, signal-based website risk assessment tool.',
    permissions: ['storage', 'activeTab', 'tabs'],
    host_permissions: ['http://localhost:3001/*'],
    optional_host_permissions: ['http://*/*', 'https://*/*'],
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'self';",
    },
    browser_specific_settings: {
      gecko: {
        id: 'webpill@example.org',
        strict_min_version: '121.0',
        data_collection_permissions: { required: ['websiteActivity'] },
      },
    },
  },
  vite: () => ({
    define: {
      'import.meta.env.WEBPILL_API_BASE_URL': JSON.stringify(process.env.WEBPILL_API_BASE_URL ?? 'http://localhost:3001'),
    },
  }),
});
