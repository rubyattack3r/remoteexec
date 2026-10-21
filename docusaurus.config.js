const {themes: prismThemes} = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'remoteexec',
  tagline: 'Authorized remote-execution assessment tooling',
  url: 'https://rubyattack3r.github.io',
  baseUrl: '/remoteexec/',
  organizationName: 'rubyattack3r',
  projectName: 'remoteexec',
  onBrokenLinks: 'throw',
  markdown: {
    mermaid: true,
  },
  themes: ['@docusaurus/theme-mermaid'],
  presets: [
    [
      'classic',
      {
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          showLastUpdateTime: true,
        },
        blog: false,
      },
    ],
  ],
  themeConfig: {
    navbar: {
      title: 'remoteexec',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {
          type: 'docsVersionDropdown',
          position: 'right',
        },
        {
          href: 'https://github.com/rubyattack3r/remoteexec',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/rubyattack3r/remoteexec'},
            {label: 'Releases', href: 'https://github.com/rubyattack3r/remoteexec/releases'},
            {label: 'Security', href: 'https://github.com/rubyattack3r/remoteexec/security/policy'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} rubyattack3r.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  },
};

module.exports = config;
