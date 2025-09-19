/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    // typedRoutes: true,
  },
  output: 'standalone',
  env: {
    CONTROLLER_API_BASE_URL: process.env.CONTROLLER_API_BASE_URL || 'http://127.0.0.1:8000',
    CONTROLLER_API_KEY:
      process.env.CONTROLLER_API_KEY || process.env.MEDUSA_ANALYST_API_KEY || '',
  },
};

export default nextConfig;
