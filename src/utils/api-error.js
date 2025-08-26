class ApiError extends Error {
  constructor(
    statusCode,
    message = "Something went wrong",
    errors = null, // allow object or array
    stack = "",
    data = null, // in case you want to return extra info
  ) {
    super(message);
    this.statusCode = statusCode;
    this.data = data;
    this.success = false;
    this.errors = errors;

    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export { ApiError };
