import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
import { NextRequest } from 'next/server';

const authHandler = handleAuth({
  login: handleLogin({
    authorizationParams: {
      audience: process.env.AUTH0_AUDIENCE,
      scope: 'openid profile email offline_access',
    },
  }),
});

export async function GET(
  req: NextRequest,
  ctx: { params: Promise<{ auth0: string }> }
) {
  const resolvedParams = await ctx.params;
  return authHandler(req, { params: resolvedParams } as any);
}

export async function POST(
  req: NextRequest,
  ctx: { params: Promise<{ auth0: string }> }
) {
  const resolvedParams = await ctx.params;
  return authHandler(req, { params: resolvedParams } as any);
}
