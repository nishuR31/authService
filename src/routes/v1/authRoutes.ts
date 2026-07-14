import {
  changePassword,
  disableTotp,
  enableTotp,
  login,
  logout,
  passless,
  passlessVerify,
  refreshToken,
  register,
  verifyTotp,
  googleLogin,
  googleCallback,
  testPassless,
  testPasslessVerify,
} from "../../controllers/authController";
import { authenticate } from "../../middlewares/authMiddleware";
import { FastifyPluginAsync } from "fastify";
import {
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  changePasswordSchema,
  googleCallbackSchema,
  passlessSchema,
  passlessVerifySchema,
  enableTotpSchema,
  verifyTotpSchema,
  disableTotpSchema,
} from "../../routeSchemas/authSchemas";

const authRouter: FastifyPluginAsync = async (app) => {
  // === Standard Auth ===
  app.post("/register", {
    schema: {
      description: "Register a new user account",
      tags: ["auth"],
      body: registerSchema
    }
  }, register);

  app.post("/login", {
    schema: {
      description: "Log in with email and password (supports TOTP multi-factor verification)",
      tags: ["auth"],
      body: loginSchema
    }
  }, login);

  app.post("/refresh-token", {
    schema: {
      description: "Rotate session tokens using refresh token",
      tags: ["auth"],
      body: refreshTokenSchema
    }
  }, refreshToken);

  app.post("/logout", {
    preHandler: authenticate as any,
    schema: {
      description: "Log out and invalidate session",
      tags: ["auth"],
      security: [{ bearerAuth: [] }]
    }
  }, logout);

  app.post("/change-password", {
    preHandler: authenticate as any,
    schema: {
      description: "Change user account password",
      tags: ["auth"],
      security: [{ bearerAuth: [] }],
      body: changePasswordSchema
    }
  }, changePassword);

  // === Google OAuth ===
  app.get("/google/login", {
    schema: {
      description: "Redirect to Google OAuth authorization page",
      tags: ["auth"]
    }
  }, googleLogin);

  app.get("/google/callback", {
    schema: {
      description: "Google OAuth callback endpoint",
      tags: ["auth"],
      querystring: googleCallbackSchema
    }
  }, googleCallback);

  // === Magic Link / Passwordless ===
  app.post("/passless", {
    schema: {
      description: "Request a passwordless magic login link to email",
      tags: ["auth"],
      body: passlessSchema
    }
  }, passless);

  app.get("/magic/verify", {
    schema: {
      description: "Verify passwordless magic link token",
      tags: ["auth"],
      querystring: passlessVerifySchema
    }
  }, passlessVerify);

  app.post("/test/passless", {
    schema: {
      description: "Request a test passwordless magic login link",
      tags: ["auth"]
    }
  }, testPassless);

  app.get("/test/magic/verify", {
    schema: {
      description: "Verify test passwordless magic link token",
      tags: ["auth"],
      querystring: passlessVerifySchema
    }
  }, testPasslessVerify);

  // === TOTP MFA ===
  app.post("/totp/enable", {
    preHandler: authenticate,
    schema: {
      description: "Initiate TOTP MFA configuration",
      tags: ["auth"],
      security: [{ bearerAuth: [] }],
      body: enableTotpSchema
    }
  }, enableTotp);

  app.post("/totp/verify", {
    preHandler: authenticate,
    schema: {
      description: "Verify and activate TOTP MFA",
      tags: ["auth"],
      security: [{ bearerAuth: [] }],
      body: verifyTotpSchema
    }
  }, verifyTotp);

  app.post("/totp/disable", {
    preHandler: authenticate,
    schema: {
      description: "Disable TOTP MFA",
      tags: ["auth"],
      security: [{ bearerAuth: [] }],
      body: disableTotpSchema
    }
  }, disableTotp);
};

export default authRouter;


