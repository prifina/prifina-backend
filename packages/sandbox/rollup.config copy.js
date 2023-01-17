import commonjs from '@rollup/plugin-commonjs';
const extensions = [".js"];

export default [
  {
    input: "src/index.js",
    output: [
      {
        exports: "auto",
        dir: "dist/cjs",
        format: "cjs",
        preserveModules: true,
      },

    ],

    plugins: [commonjs({
      ignoreDynamicRequires: true
    })]
  },
];
