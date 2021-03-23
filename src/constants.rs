// Messages
pub const MESSAGE_OK: &str = "ok";
pub const MESSAGE_LOGIN_SUCCESS: &str = "Login successfully";
pub const MESSAGE_LOGIN_FAILED: &str = "Wrong username or password, please try again";
pub const MESSAGE_USER_NOT_FOUND: &str = "User not found";
pub const MESSAGE_LOGOUT_SUCCESS: &str = "Logout successfully";
pub const MESSAGE_PROCESS_TOKEN_ERROR: &str = "Error while processing token";
pub const MESSAGE_INVALID_TOKEN: &str = "Invalid token, please login again";
pub const MESSAGE_INTERNAL_SERVER_ERROR: &str = "Internal Server Error";

// Bad request messages
pub const MESSAGE_TOKEN_MISSING: &str = "Token is missing";

// Headers
pub const AUTHORIZATION: &str = "Authorization";

// Misc
pub const EMPTY: &str = "";

// ignore routes
pub const IGNORE_ROUTES: [&str; 2] = ["/api/ping", "/api/auth/login"];
