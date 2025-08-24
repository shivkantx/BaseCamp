import express from "express";
import cors from "cors";

const app = express();

// basic configurations
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send("Welcome to basecampy");
});

// cors configurations
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:8000",
    credentials: true,
    methods: ["GET", " POST", "POT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

export default app;
