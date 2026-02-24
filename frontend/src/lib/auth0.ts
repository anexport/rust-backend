import { Auth0Client } from '@auth0/nextjs-auth0/server';

let _auth0: Auth0Client | null = null;

export const auth0: Auth0Client = new Proxy({} as Auth0Client, {
  get(target, prop) {
    if (!_auth0) {
      const authorizationParameters: { audience?: string; scope: string } = {
        scope: 'openid profile email offline_access',
      };

      if (process.env.AUTH0_AUDIENCE) {
        authorizationParameters.audience = process.env.AUTH0_AUDIENCE;
      }

      const appBaseUrl = process.env.APP_BASE_URL || process.env.AUTH0_BASE_URL;
      if (!appBaseUrl) {
        throw new Error(
          'Missing required environment variable: APP_BASE_URL or AUTH0_BASE_URL must be set'
        );
      }

      _auth0 = new Auth0Client({
        appBaseUrl,
        authorizationParameters,
      });
    }
    const value = Reflect.get(_auth0, prop);
    // Bind methods to the instance so `this` is correct when called
    return typeof value === 'function' ? value.bind(_auth0) : value;
  },
});
