import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'Zoe Relay Documentation',
  tagline: 'Secure, decentralized messaging infrastructure',
  favicon: 'img/favicon.ico',
  
  headTags: [
    {
      tagName: 'link',
      attributes: {
        rel: 'icon',
        type: 'image/png',
        sizes: '16x16',
        href: '/img/favicon-16x16.png',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'icon',
        type: 'image/png',
        sizes: '32x32',
        href: '/img/favicon-32x32.png',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'apple-touch-icon',
        sizes: '192x192',
        href: '/img/favicon-192x192.png',
      },
    },
  ],

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // Set the production url of your site here
  url: 'https://acterglobal.github.io',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: process.env.NODE_ENV === 'development' ? '/' : '/zoe-relay/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'acterglobal', // Usually your GitHub org/user name.
  projectName: 'zoe-relay', // Usually your repo name.

  onBrokenLinks: 'warn', // Changed to warn for now since rustdoc doesn't exist yet
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/acterglobal/zoe-relay/tree/main/docs/',
          // Using Docusaurus built-in code import instead of custom plugin
        },
        blog: false, // Disable blog for now
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // Zoe Relay branded social card
    image: 'img/zoe-social-card.jpg',
    navbar: {
      title: 'Zoe Relay',
      logo: {
        alt: 'Zoe Relay Logo',
        src: 'img/zoe-logo.png',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'tutorialSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {
          href: process.env.NODE_ENV === 'development' ? 'http://localhost:8000/rustdoc/' : '/zoe-relay/rustdoc/',
          label: 'Rust API Docs',
          position: 'left',
        },
        {
          href: 'https://github.com/acterglobal/zoe-relay',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Administration',
              to: '/docs/administration/overview',
            },
            {
              label: 'Developer',
              to: '/docs/architecture/overview',
            },
          ],
        },
        {
          title: 'API Reference',
          items: [
            {
              label: 'Rust API Documentation',
              href: process.env.NODE_ENV === 'development' ? 'http://localhost:8000/rustdoc/' : '/zoe-relay/rustdoc/',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/acterglobal/zoe-relay',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Acter. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['rust', 'toml'],
    },
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: false,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
