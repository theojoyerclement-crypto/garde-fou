import { describe, expect, it } from 'vitest';
import { isSensitiveName, publicPrefixOf } from '../src/rules/env';

describe('isSensitiveName', () => {
  it.each([
    'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
    'NEXT_PUBLIC_STRIPE_SECRET_KEY',
    'VITE_OPENAI_API_KEY',
    'VITE_ANTHROPIC_API_KEY',
    'EXPO_PUBLIC_DATABASE_URL',
    'REACT_APP_JWT_SECRET',
    'NEXT_PUBLIC_GITHUB_CLIENT_SECRET',
    'VITE_ADMIN_PASSWORD',
    'NEXT_PUBLIC_FIREBASE_PRIVATE_KEY',
  ])('flags %s', (name) => {
    expect(isSensitiveName(name)).toBe(true);
  });

  it.each([
    'NEXT_PUBLIC_SUPABASE_ANON_KEY',
    'NEXT_PUBLIC_SUPABASE_URL',
    'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
    'VITE_OPENAI_MODEL',
    'NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN',
    'VITE_API_URL',
    'NEXT_PUBLIC_POSTHOG_KEY',
    'NEXT_PUBLIC_SECRETARIAT_EMAIL',
  ])('does not flag %s', (name) => {
    expect(isSensitiveName(name)).toBe(false);
  });
});

describe('publicPrefixOf', () => {
  it('returns the client-side prefix', () => {
    expect(publicPrefixOf('NEXT_PUBLIC_X')).toBe('NEXT_PUBLIC_');
    expect(publicPrefixOf('VITE_X')).toBe('VITE_');
    expect(publicPrefixOf('STRIPE_SECRET_KEY')).toBeNull();
  });
});
