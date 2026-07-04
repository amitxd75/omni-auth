/**
 * @file index.ts
 * Public barrel export for @omni-auth/core.
 *
 * Import anything you need from this single entry-point:
 *
 * ```ts
 * import { OmniAuthClient, OmniAuthError, MfaRequiredError } from '@omni-auth/core';
 * import type { User, AuthResponse, OmniAuthConfig } from '@omni-auth/core';
 * ```
 */

export * from './types';
export * from './errors';
export * from './client';
export * from './jwt';
