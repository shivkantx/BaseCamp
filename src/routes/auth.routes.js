import { Router } from "express";
import { login, registerUser } from "../controllers/auth.controller.js";

import { validate } from "../middlewares/validator.middleware.js";

import {
  userRegisterValidator,
  userLoginValidator,
} from "../validators/index.js";
const router = Router();
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").get(userLoginValidator(), login);

export default router;
