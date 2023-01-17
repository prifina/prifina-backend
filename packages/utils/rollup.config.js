import commonjs from '@rollup/plugin-commonjs';
import babel from "@rollup/plugin-babel";
import resolve from "@rollup/plugin-node-resolve";
import json from "@rollup/plugin-json";

import externals from "rollup-plugin-node-externals";

const extensions = [".js"];

export default [
  {
    input: "src/index.js",
    output: [
      {
        exports: "auto",
        dir: "dist/cjs",
        format: "cjs",
        //preserveModules: true,
      },
      {
        dir: "dist/esm",
        format: "esm",
      },

    ],

    plugins: [externals(), json(), commonjs({
      ignoreDynamicRequires: true
    }),
    resolve({ extensions }),
    babel({
      babelHelpers: "bundled",
      include: ["src/**/*.js"],
      extensions,
      exclude: "./node_modules/**",
    }),]
  },
];
