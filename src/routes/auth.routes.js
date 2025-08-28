import { Router } from "express";
import {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordRequest,
  resetForgotPassword,
  changeCurrentPassword,
} from "../controllers/auth.controller.js";

import { validate } from "../middlewares/validator.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

import {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
} from "../validators/index.js";

const router = Router();

// Public routes (no auth required)
router.post("/register", userRegisterValidator(), validate, registerUser);
router.post("/login", userLoginValidator(), validate, login);
router.get("/verify-email/:verificationToken", verifyEmail);
router.post(
  "/forgot-password",
  userForgotPasswordValidator(),
  validate,
  forgotPasswordRequest,
);
router.post(
  "/reset-password/:resetToken",
  userResetForgotPasswordValidator(),
  validate,
  resetForgotPassword,
);
router.post("/refresh-token", refreshAccessToken);

// Protected routes (auth required)
router.post("/logout", verifyJWT, logoutUser);
router.post("/resend-email-verification", verifyJWT, resendEmailVerification);
router.post(
  "/change-password",
  verifyJWT,
  userChangeCurrentPasswordValidator(),
  validate,
  changeCurrentPassword,
);
router.get("/current-user", verifyJWT, getCurrentUser);

export default router;
