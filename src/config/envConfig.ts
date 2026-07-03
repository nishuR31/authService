import dotenv from "dotenv";
dotenv.config();

export const PORT: number = Number(process.env.PORT) || 3001;
export const DATABASE_URL: string = process.env.DATABASE_URL;
export const NODE_ENV: string = process.env.NODE_ENV || "development";
export const BCRYPT_SALT_ROUND: number = Number(process.env.BCRYPT_SALT_ROUND) || 10;
export const LOG_LEVEL: string =
  process.env.LOG_LEVEL || (NODE_ENV === "development" ? "debug" : "info");

export const SMTP_HOST: string = process.env.SMTP_HOST || "smtp.gmail.com";
export const SMTP_PORT: number = parseInt(process.env.SMTP_PORT || "587", 10);
export const SMTP_USER: string = process.env.SMTP_USER || "";
export const SMTP_PASSWORD: string = process.env.SMTP_PASSWORD || "";
export const SMTP_FROM_NAME: string = process.env.SMTP_FROM_NAME || "AuthService";
export const SMTP_FROM_EMAIL: string = process.env.SMTP_FROM_EMAIL || "noreply@authservice.com";

export const REDIS_URL: string = process.env.REDIS_URL || "redis://localhost:6379";

export const JWT_ACCESS_SECRET: string = process.env.JWT_ACCESS_SECRET || "dev-access-secret";
export const JWT_REFRESH_SECRET: string = process.env.JWT_REFRESH_SECRET || "dev-refresh-secret";
export const JWT_ACCESS_EXPIRY: string = process.env.JWT_ACCESS_EXPIRY || "1h";
export const JWT_REFRESH_EXPIRY: string = process.env.JWT_REFRESH_EXPIRY || "7d";

export const GOOGLE_CLIENT_ID: string = process.env.GOOGLE_CLIENT_ID || "";
export const GOOGLE_CLIENT_SECRET: string = process.env.GOOGLE_CLIENT_SECRET || "";
export const GOOGLE_REDIRECT_URI: string =
  process.env.GOOGLE_REDIRECT_URI || "http://localhost:3000/api/v1/auth/google/callback";

export const TOTP_ISSUER: string = process.env.TOTP_ISSUER || "Auth Service";
