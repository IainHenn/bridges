import type { NextConfig } from 'next';
console.log('Loaded next.config.ts');

const nextConfig: NextConfig = {

  async rewrites() {
    return [
      {
        source: '/:path*',
        destination: 'http://localhost:8080/:path*',
      },
    ];
  },
};

export default nextConfig;
