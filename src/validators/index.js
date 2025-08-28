import { body } from "express-validator";

/**
 * Register validator
 * - expects: email, username, password
 * - optional: fullName
 */
const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()
      .withMessage("Username must be in lowercase")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),

    // NOTE: changed to match schema field name
    body("fullName").optional().trim(),
  ];
};

/**
 * Login validator
 * - Accepts either username OR email (one required) + password
 * - If email provided, it must be valid. If username provided, must be non-empty.
 */
const userLoginValidator = () => {
  return [
    // either email or username must exist — enforce using a custom validator
    body().custom((_, { req }) => {
      const hasEmail = !!req.body.email;
      const hasUsername = !!req.body.username;

      if (!hasEmail && !hasUsername) {
        throw new Error("Either username or email is required");
      }
      return true;
    }),

    // if email is present, validate it
    body("email").optional().isEmail().withMessage("Email is invalid"),

    // if username is present, ensure it's non-empty (and lowercase if you want)
    body("username")
      .optional()
      .trim()
      .notEmpty()
      .withMessage("Username is required"),
  ];
};

/**
 * Change current password validator
 */
const userChangeCurrentPasswordValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("Old password is required"),
    body("newPassword")
      .notEmpty()
      .withMessage("New password is required")
      .isLength({ min: 6 })
      .withMessage("New password must be at least 6 characters long"),
  ];
};

/**
 * Forgot password validator
 */
const userForgotPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
  ];
};

/**
 * Reset forgot password validator
 */
const userResetForgotPasswordValidator = () => {
  return [
    body("newPassword")
      .notEmpty()
      .withMessage("New password is required")
      .isLength({ min: 6 })
      .withMessage("New password must be at least 6 characters long"),
  ];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
};
