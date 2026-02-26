import { Auth0Client } from '@auth0/nextjs-auth0/server';

const appBaseUrl = process.env.APP_BASE_URL || process.env.AUTH0_BASE_URL || undefined;

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

      _auth0 = new Auth0Client({
        appBaseUrl,
        authorizationParameters,
      });
    }
    const value = Reflect.get(_auth0, prop);
    return typeof value === 'function' ? value.bind(_auth0) : value;
  },
  set(target, prop, value) {
    if (!_auth0) {
      const authorizationParameters: { audience?: string; scope: string } = {
        scope: 'openid profile email offline_access',
      };

      if (process.env.AUTH0_AUDIENCE) {
        authorizationParameters.audience = process.env.AUTH0_AUDIENCE;
      }

      _auth0 = new Auth0Client({
        appBaseUrl,
        authorizationParameters,
      });
    }
    return Reflect.set(_auth0, prop, value);
  },
  has(target, prop) {
    if (!_auth0) {
      const authorizationParameters: { audience?: string; scope: string } = {
        scope: 'openid profile email offline_access',
      };

      if (process.env.AUTH0_AUDIENCE) {
        authorizationParameters.audience = process.env.AUTH0_AUDIENCE;
      }

      _auth0 = new Auth0Client({
        appBaseUrl,
        authorizationParameters,
      });
    }
    return Reflect.has(_auth0, prop);
  },
});
