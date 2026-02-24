import { Auth0Client } from '@auth0/nextjs-auth0/server';

const authorizationParameters: { audience?: string; scope: string } = {
  scope: 'openid profile email offline_access',
};

if (process.env.AUTH0_AUDIENCE) {
  authorizationParameters.audience = process.env.AUTH0_AUDIENCE;
}

export const auth0 = new Auth0Client({
  appBaseUrl: process.env.APP_BASE_URL || process.env.AUTH0_BASE_URL || 'http://localhost:3000',
  authorizationParameters,
});
