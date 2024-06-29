# JWT Authentication using Passport-JWT in Express

This repository demonstrates how to implement JWT authentication with access and refresh token functionality using passport-jwt in an Express.js application.

Sure, I'll add a section to explain the flow of authentication in your README file:

---


## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/X-DEV-JOHNDOE/role-based-auth.git
   cd role-based-auth
   ```

2. Install the dependencies:
   ```bash
   npm install
   ```

3. Set up your environment variables. Create a `.env` file in the root directory of the project and add the following:
   ```
   DATABASE_URL=your_database_url
   ACCESS_TOKEN_SECRET=your_access_token_secret
   REFRESH_TOKEN_SECRET=your_refresh_token_secret
   NODE_ENV=development
   ```

## Configuration

- `DATABASE_URL`: URL of your PostgreSQL database.
- `ACCESS_TOKEN_SECRET`: Secret key for signing access tokens.
- `REFRESH_TOKEN_SECRET`: Secret key for signing refresh tokens.
- `NODE_ENV`: Set to `production` in a production environment.

## Authentication Flow

1. **Registration**: 
   - The user registers by sending a `POST` request to `/api/v1/register` with their username, email, and password.
   - The server hashes the password and stores the user information in the database.
   - The server generates a refresh token and an access token, and sends them back to the client. The refresh token is stored in an HttpOnly cookie.

2. **Login**:
   - The user logs in by sending a `POST` request to `/api/v1/login` with their username and password.
   - The server validates the credentials, and if valid, generates a new refresh token and access token.
   - The refresh token is stored in an HttpOnly cookie, and the access token is sent in the response body.

3. **Accessing Protected Routes**:
   - The client sends requests to protected routes with the access token in the `Authorization` header.
   - The server uses Passport-JWT to authenticate the access token. If the token is valid, the request proceeds. If not, the server checks for a refresh token.

4. **Token Refresh**:
   - If the access token is expired or invalid, the server checks for a refresh token in the cookies.
   - The server verifies the refresh token. If valid, a new access token is generated and sent to the client.
   - If the refresh token is invalid or expired, the user has to log in again.

5. **Logout**:
   - The user logs out by sending a `GET` request to `/api/v1/logout`.
   - The server clears the refresh token cookie, effectively logging the user out.

## Usage

1. Start the server:
   ```bash
   npm start
   ```

2. The server will run on `http://localhost:4000`.

## Endpoints

- `POST /api/v1/register`: Register a new user
  - Request body: `{ "username": "string", "email": "string", "password": "string" }`
  - Response: `{ "accessToken": "string", "role": "string" }`

- `POST /api/v1/login`: Log in a user
  - Request body: `{ "username": "string", "password": "string" }`
  - Response: `{ "accessToken": "string", "role": "string" }`

- `GET /api/v1/logout`: Log out the user and clear the refresh token cookie
  - Response: `"successfully, logged out"`

- `GET /api/v1/protected/admin/dashboard`: Access admin dashboard
  - Requires `admin` role
  - Response: `{ "message": "welcome, admin" }`

- `GET /api/v1/protected/user/profile`: Access user profile
  - Requires `user` role
  - Response: `{ "message": "welcome, user" }`

## Security Considerations

- Store refresh tokens as HttpOnly cookies to prevent access via JavaScript.
- Ensure you use secure cookies in production by setting the `secure` flag.
- Use strong secret keys for signing tokens.
- Validate and sanitize all user inputs to prevent SQL injection and other attacks.

