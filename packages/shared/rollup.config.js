import commonjs from '@rollup/plugin-commonjs';

//import babel from "@rollup/plugin-babel";
//import resolve from "@rollup/plugin-node-resolve";

const extensions = [".js"];

export default [
  {
    input: "lib/index.js",
    output: [
      {
        exports: "auto",
        dir: "dist/cjs",
        format: "cjs",
        preserveModules: true,
      },

    ],

    plugins: [commonjs()]
  },
];
