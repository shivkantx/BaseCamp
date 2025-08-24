// healthcheck.controller.js
import { ApiResponse } from "../utils/api-response.js";

const healthCheck = (req, res) => {
  try {
    return res
      .status(200)
      .json(new ApiResponse(200, { message: "Server is running ✅" }));
  } catch (error) {
    console.error("❌ Health check failed:", error);
    return res
      .status(500)
      .json(new ApiResponse(500, { message: "Internal server error" }));
  }
};

export default healthCheck;
