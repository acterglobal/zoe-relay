import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
  // Manually defined sidebar for better organization
  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Administration',
      items: [
        'administration/overview',
        // TODO: Add more administration documentation
        // 'administration/installation',
        // 'administration/configuration',
        // 'administration/deployment',
        // 'administration/monitoring',
        // 'administration/troubleshooting',
      ],
    },
    {
      type: 'category',
      label: 'Developer',
      items: [
        {
          type: 'category',
          label: 'Architecture',
          items: [
            'architecture/overview',
            {
              type: 'category',
              label: 'Groups',
              items: [
                'architecture/groups/invitation-flow',
              ],
            },
            {
              type: 'category',
              label: 'PQXDH Protocol',
              items: [
                'architecture/pqxdh/overview',
                'architecture/pqxdh/key-exchange',
                'architecture/pqxdh/session-management',
              ],
            },
            {
              type: 'category',
              label: 'Wire Protocol',
              items: [
                'architecture/wire-protocol/serialization',
                'architecture/wire-protocol/message-types',
              ],
            },
          ],
        },
        {
          type: 'category',
          label: 'Development',
          items: [
            'development/setup',
            'development/testing',
            'development/code-examples',
            'development/contributing',
          ],
        },
        {
          type: 'category',
          label: 'Crate Documentation',
          items: [
            'crates-app-primitives',
            'crates-wire-protocol',
            'crates-client',
            'crates-relay',
          ],
        },
      ],
    },
  ],
};

export default sidebars;
