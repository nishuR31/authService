// import { Router } from "express";
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
} from "../../controllers/authController";
import { authenticate } from "../../middlewares/authMiddleware";
import { FastifyPluginAsync } from "fastify";
import { FastifyApp } from "../../types";

const authRouter: FastifyPluginAsync = async (app) => {
  app.post("/register", register);
  app.post("/login", login);
  app.post("/refresh-token", refreshToken);

  app.post("/logout", { preHandler: authenticate as any }, logout);
  app.post("/change-password", { preHandler: authenticate as any }, changePassword);

  app.post("/totp/enable", { preHandler: authenticate }, enableTotp);
  app.post("/totp/verify", { preHandler: authenticate }, verifyTotp);
  app.post("/totp/disable", { preHandler: authenticate }, disableTotp);
}
export default authRouter;
