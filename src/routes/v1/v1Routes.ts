import authRouter from "./authRoutes";
import { FastifyInstance } from "fastify";
import { healthRoutes } from "./health";
import { pingRoutes } from "./ping";
import { version } from "./version";
import { publicRoutes } from "./public";

const v1Router = async (app: FastifyInstance) => {
  app.register(publicRoutes);
  app.register(authRouter, { prefix: "/auth" });
  app.register(healthRoutes);
  app.register(pingRoutes);
  app.register(version);
};

export default v1Router;
