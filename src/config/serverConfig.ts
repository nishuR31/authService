import fastify, { FastifyReply, FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";

// let isDev = process.env.NODE_ENV === "dev";

let fastifyApp = fastify({ logger: true, exposeHeadRoutes: true });
fastifyApp.register(cors, { origin: true });
fastifyApp.register(cookie);

fastifyApp.get("/", (req: FastifyRequest, res: FastifyReply) => {
  res.code(200).send({ message: "Server fired up" });
});

export default fastifyApp;
export type { fastifyApp };
