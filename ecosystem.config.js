module.exports = {
  apps: [
    {
      name: 'kiera-web-server',
      script: './server/start.js',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'development'
      },
      env_production: {
        NODE_ENV: 'production'
      }
    }
  ],

  deploy: {
    production: {
      'post-deploy': 'yarn install && pm2 reload ecosystem.config.js --env production'
    }
  }
}
