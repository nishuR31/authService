import authRouter from "./authRoutes";
import { FastifyPluginAsync } from "fastify";

const v1Router: FastifyPluginAsync = async (app) => {
  app.register(authRouter, { prefix: "/auth" });
};

export default v1Router;
