import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

const opts = { $refStrategy: "none" } as const;

// ─── Zod definitions ────────────────────────────────────────────────────────

const _registerZod = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  password: z.string().min(6),
  phone: z.string().optional(),
  gender: z.string().min(1),
});

const _loginZod = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  totpToken: z.string().length(6).optional(),
});

const _refreshTokenZod = z.object({
  refreshToken: z.string().optional(),
});

const _changePasswordZod = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(6),
});

const _googleCallbackZod = z.object({
  code: z.string().optional(),
  state: z.string().optional(),
  error: z.string().optional(),
});

const _passlessZod = z.object({
  email: z.string().email(),
});

const _passlessVerifyZod = z.object({
  token: z.string().min(1),
  role: z.string().min(1),
});

const _enableTotpZod = z.object({
  password: z.string().min(1),
});

const _verifyTotpZod = z.object({
  token: z.string().length(6),
});

const _disableTotpZod = z.object({
  password: z.string().min(1),
});

// ─── JSON Schema exports ─────────────────────────────────────────────────────

export const registerSchema = zodToJsonSchema(_registerZod as any, opts);
export const loginSchema = zodToJsonSchema(_loginZod as any, opts);
export const refreshTokenSchema = zodToJsonSchema(_refreshTokenZod as any, opts);
export const changePasswordSchema = zodToJsonSchema(_changePasswordZod as any, opts);
export const googleCallbackSchema = zodToJsonSchema(_googleCallbackZod as any, opts);
export const passlessSchema = zodToJsonSchema(_passlessZod as any, opts);
export const passlessVerifySchema = zodToJsonSchema(_passlessVerifyZod as any, opts);
export const enableTotpSchema = zodToJsonSchema(_enableTotpZod as any, opts);
export const verifyTotpSchema = zodToJsonSchema(_verifyTotpZod as any, opts);
export const disableTotpSchema = zodToJsonSchema(_disableTotpZod as any, opts);
