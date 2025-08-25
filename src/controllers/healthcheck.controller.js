// healthcheck.controller.js
import { ApiResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/async-handler.js";

/** 
const healthCheck = async (req, res, next) => {
  try {
    // Optional: test DB connection if needed
    // await mongoose.connection.db.admin().ping();

    return res
      .status(200)
      .json(new ApiResponse(200, { message: "✅ Server is running" }));
  } catch (err) {
    console.error("❌ Health check failed:", err);
    return next(err); // pass error to Express error handler
  }
};
*/

const healthCheck = asyncHandler(async (req, res) => {
  res
    .status(200)
    .json(new ApiResponse(200, { message: "✅ Server is running" }));
});

export default healthCheck;
