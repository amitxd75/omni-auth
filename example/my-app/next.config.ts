import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  transpilePackages: ["@omni-auth/core", "@omni-auth/react"],
  experimental: {
    externalDir: true,
  },
  webpack(config) {
    config.resolve.alias = {
      ...config.resolve.alias,
      "@omni-auth/core": path.resolve(__dirname, "../../sdk/core/src/index.ts"),
      "@omni-auth/react": path.resolve(__dirname, "../../sdk/react/src/index.ts"),
    };
    // Always resolve modules from the app's node_modules so SDK source files
    // can find react, react-dom etc. without their own node_modules.
    config.resolve.modules = [
      path.resolve(__dirname, "node_modules"),
      "node_modules",
    ];
    return config;
  },
};

export default nextConfig;
