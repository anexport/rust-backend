import { Auth0Client } from '@auth0/nextjs-auth0/server';

const appBaseUrl = process.env.APP_BASE_URL || process.env.AUTH0_BASE_URL || undefined;

let _auth0: Auth0Client | null = null;

function getAuth0Client(): Auth0Client {
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
  return _auth0;
}

export const auth0: Auth0Client = new Proxy({} as Auth0Client, {
  get(target, prop) {
    const auth0Client = getAuth0Client();
    const value = Reflect.get(auth0Client, prop);
    return typeof value === 'function' ? value.bind(auth0Client) : value;
  },
  set(target, prop, value) {
    return Reflect.set(getAuth0Client(), prop, value);
  },
  has(target, prop) {
    return Reflect.has(getAuth0Client(), prop);
  },
});
