import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
dotenv.config();

import authRoutes from "./routes/auth.js";
import { pool } from "./db.js";

const app = express();

app.use(express.json());
app.use(cookieParser());

// Allow frontend (Next.js) to use cookies
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));

app.use("/auth", authRoutes);

app.listen(4000, () => console.log("Server running on port 4000"));
