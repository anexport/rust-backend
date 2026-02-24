# Frontend Setup Guide (For User)

This guide outlines the steps you need to take to initialize the Next.js frontend project with the required stack. Once you complete these steps, the AI will be able to take over and build out the features.

## Prerequisites
- Node.js installed (v18.17 or later)
- An active Auth0 Tenant

## Step 1: Clean Up the Old Frontend

Remove the existing minimal HTML file to make room for the new Next.js application.

```bash
rm -rf frontend
```

## Step 2: Initialize Next.js Application

Create a new Next.js project named `frontend`. Ensure you select the following options when prompted (or use the flags below to automate it).

```bash
npx create-next-app@latest frontend 
  --typescript 
  --tailwind 
  --eslint 
  --app 
  --src-dir 
  --import-alias "@/*" 
  --use-npm
```

## Step 3: Install and Configure shadcn/ui

Navigate into the new `frontend` directory and initialize shadcn/ui.

```bash
cd frontend
npx shadcn@latest init
```

*When prompted, choose the following (or your preferred equivalents):*
- Style: **Default**
- Base color: **Slate**
- CSS variables: **yes**

Next, install the required shadcn components that the AI will use to build the UI:

```bash
npx shadcn@latest add button card dialog dropdown-menu form input label select separator skeleton table tabs textarea toast avatar
```

## Step 4: Install Dependencies

Install the Auth0 Next.js SDK, which will handle the authentication flow. We will also install `lucide-react` for icons (which shadcn uses by default) and `date-fns` for formatting dates.

```bash
npm install @auth0/nextjs-auth0 lucide-react date-fns
```

## Step 5: Configure Auth0 Environment Variables

Create a `.env.local` file inside the `frontend` directory:

```bash
touch .env.local
```

Add the following environment variables. **You will need to retrieve your Auth0 credentials from your Auth0 Dashboard.**

```env
# A long secret value used to encrypt the session cookie
# You can generate one with: openssl rand -hex 32
AUTH0_SECRET='your_super_secret_32_character_string_here'

# The base URL of your application
AUTH0_BASE_URL='http://localhost:3000'

# Your Auth0 application's Issuer Base URL
AUTH0_ISSUER_BASE_URL='https://YOUR_TENANT.us.auth0.com'

# Your Auth0 application's Client ID
AUTH0_CLIENT_ID='YOUR_CLIENT_ID'

# Your Auth0 application's Client Secret
AUTH0_CLIENT_SECRET='YOUR_CLIENT_SECRET'

# Important: This must match the expected Audience in the Rust backend
AUTH0_AUDIENCE='https://api.your-app.example'

# The URL of the local Rust backend
NEXT_PUBLIC_API_URL='http://localhost:8080'
```

*Make sure your Auth0 application is configured to allow callbacks to `http://localhost:3000/api/auth/callback` and logouts to `http://localhost:3000`.*

## Step 6: Verify and Handover

Start the Next.js development server to verify everything installed correctly:

```bash
npm run dev
```

Once the server runs successfully and you have configured the `.env.local` variables, you are done with the manual setup! 

**You can now ask the AI to "start executing the AI Build Plan".**
