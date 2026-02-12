/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Use 'export' for static generation (Electron compatible)
  // Use 'standalone' for Docker/server deployment
  output: process.env.BUILD_MODE === 'electron' ? 'export' : 'standalone',

  // Enable trailing slash for static export file routing
  trailingSlash: process.env.BUILD_MODE === 'electron',

  // Use relative paths for assets in Electron (file:// protocol)
  assetPrefix: process.env.BUILD_MODE === 'electron' ? './' : undefined,

  // Server Actions configuration
  experimental: {
    serverActions: {
      bodySizeLimit: '10mb',
    },
  },

  // API proxy for backend (only works in standalone mode)
  // In static export mode, frontend calls API directly
  async rewrites() {
    if (process.env.BUILD_MODE === 'electron') {
      return [];
    }

    const backendBaseUrl =
      process.env.NEXT_PUBLIC_BACKEND_URL ||
      process.env.NEXT_PUBLIC_API_URL ||
      'http://localhost:4000';

    return [
      {
        source: '/api/:path*',
        destination: `${backendBaseUrl}/api/:path*`,
      },
    ];
  },

  // Environment variables available at build time
  env: {
    NEXT_PUBLIC_DEFAULT_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000',
  },
};

module.exports = nextConfig;

