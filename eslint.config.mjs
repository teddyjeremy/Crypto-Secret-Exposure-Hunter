import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FlatCompat } from "@eslint/eslintrc";
const compat = new FlatCompat({ baseDirectory: dirname(fileURLToPath(import.meta.url)) });
export default [
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    rules: {
      // API payloads and driver-returned rows are validated at runtime before use.
      "@typescript-eslint/no-explicit-any": "off"
    }
  }
];
