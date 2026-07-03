import app from "./app";
import { PORT, NODE_ENV } from "./config/envConfig";
import redis, { disconnectRedis } from "./config/redisConfig";
import logger from "./config/loggerConfig";

const startServer = async () => {
  try {
    const address = await app.listen({ port: PORT, host: "0.0.0.0" });
  } catch (err: any) {
    logger.error(err?.message || err);
    process.exit(1);
  }
};

startServer();
redis.connect();
async function gracefulShutdown(signal: string) {
  logger.info(`\n Received ${signal}. Shutting down gracefully…`);

  app.close(async () => {
    logger.info("HTTP server closed.");

    try {
      await disconnectRedis();
    } catch (err) {
      logger.error("Error dismounting RAM", { error: err });
    }

    logger.info("All connections closed. Goodbye!");
    process.exit(0);
  });

  setTimeout(() => {
    logger.error("Shutdown timed out. Forcing exit.");
    process.exit(1);
  }, 10_000);
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

process.on("unhandledRejection", (reason: any) => {
  logger.error("Unhandled Rejection", { error: reason?.message || reason });
});

process.on("uncaughtException", (error: Error) => {
  logger.error("Uncaught Exception", {
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
});
