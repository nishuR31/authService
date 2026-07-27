import type { FastifyInstance } from "fastify";
import env from "../../config/envConfig.js";
import currentVersion from "../../utils/helpers/version.js";
import { sendSuccess } from "../../utils/common/response.js";

export async function pingRoutes(app: FastifyInstance) {
  app.get("/ping", async (req: Request, res: Response) => {
    return sendSuccess(res, "pong", 200, { service: env.BUSINESS_NAME || "RanchiKart", version: currentVersion });
  });
}
