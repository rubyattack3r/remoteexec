/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docsSidebar: [
    'index',
    'architecture',
    'platforms',
    {
      type: 'category',
      label: 'Techniques',
      items: [
        'techniques/wmiprovider',
        'techniques/wmiservice',
        'techniques/wmiexec',
        'techniques/wsmanexec',
        'techniques/taskschedexec',
        'techniques/dcomishelldispatch2',
        'techniques/scmchangeservice',
        'techniques/scmcreateservice',
        'techniques/sshexec',
      ],
    },
    'configuration',
    {
      type: 'category',
      label: 'Launchers',
      items: [
        'launchers/index',
        'launchers/authoring',
        'launchers/native',
        'launchers/cpl',
        'launchers/managed',
        'launchers/injection',
        'launchers/custom',
      ],
    },
    'output',
    'recovery',
    {
      type: 'category',
      label: 'Development',
      items: [
        'development/index',
        'development/setup',
        'development/releasing',
      ],
    },
  ],
};

module.exports = sidebars;
