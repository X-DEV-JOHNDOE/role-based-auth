import env from "dotenv";
import express from "express";
import cookieParser from "cookie-parser";
import pg from "pg";
import passport from "passport";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import passportJWT from "passport-jwt";  
import cors from 'cors';

env.config();
const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;
const saltRounds = 10;

// Create Express App
const app = express();
const PORT = 4000;
const admins = [
  { id: 1, name: "JohnDoe" },
  { id: 2, name: "JoeBloggs" }
]

// Middleware
app.use(express.json());
app.use(cookieParser());
const allowedOrigins = ["http://localhost:3000"];

app.use(
  cors({
    origin: (origin, callback) => {
      if (allowedOrigins.indexOf(origin) !== -1 || !origin) callback(null, true);
      else callback(new Error("Origin not allowed by CORS"));
    },
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
    optionsSuccessStatus: 204,
  })
);

// Database Connection Pooling
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 3000, 
  idleTimeoutMillis: 2000, 
  max: 4 
});


// JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // extract the access token from the authorization header  
  secretOrKey: process.env.ACCESS_TOKEN_SECRET,
};

passport.use(new JwtStrategy(jwtOptions, async (jwtPayload, callback) => {
  // if jwt is invalid or missing then it will call callback(null, false) immediately 
  // hense will not enter in this fuction body
  // it is like next(null, false) (** just for understanding **)
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT id FROM users WHERE id = $1', [jwtPayload.sub]);
    client.release();
    const user = result.rows[0];
    if (user) {
      user.role = admins.some(u => u.id === user.id) ? "admin" : "user";
      callback(null, user);
    } else {
      callback(null, false);
    }
  } catch (error) {
    callback(error, false);
  }
}));

// Initialize Passport
app.use(passport.initialize()); 


// first implementation - logic separated in different middlewares ~~~~~~~~~~~~~~~~~~~
const authenticateJWT = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user) => {
    if (err || !user) {
      console.log(err);
      console.log(user);
      req.isAuthenticated = false;
    } else {
      req.isAuthenticated = true;
      req.user = user; // id, role
    }
    next();
  })(req, res, next);
};

const handleNewAccessToken = async (req, res, next) => {
  if (!req.isAuthenticated) {
    // access token is not valid or user not found
    const refreshToken = req.cookies?.['refresh-token'];
    if (!refreshToken) {
      // in this case, redirect to login or home page 
      return res.status(401).json({ message: 'Unauthorized: No refresh token provided' });
    }
    // Verify refresh token
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
      if (err) {
        // in this case, redirect to login or home page 
        return res.status(403).json({ message: 'Unauthorized: Invalid refresh token' });
      } else {
         // Refresh token is valid, issue a new access token
        const role =  admins.some(u => u.id === decoded.sub) ? "admin" : "user";
        const newAccessToken = jwt.sign(
          { 
            sub: decoded.sub,
            iat: Math.floor(Date.now() / 1000),
            role: role
          },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: '15m' }
        );
        req.user = { id: decoded.sub, role: role }; // id, role
        res.locals.newAccessToken = newAccessToken;
      }
    });
  }
  next();
};

const verifyRoles = (...allowedRoles) =>{
  return (req, res, next) =>{
    if(!req.user?.role) return res.sendStatus(401);
    const result = allowedRoles.some(role => role === req.user.role);
    if(!result) return res.sendStatus(401);
    else if(res.locals.newAccessToken) return res.status(200).json({ accessToken: res.locals.newAccessToken });
    next();
  }
}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


// second implementation - entire logic in one middleware ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// const authenticate = (...allowedRoles) =>{
//   return (req, res, next)=>{
//     passport.authenticate('jwt', {session: false}, (err, user)=>{
//       if (err || !user) {
//         console.log(err);
//         console.log(!user);
//         // access token is not valid or user not found
//         const refreshToken = req.cookies?.['refresh-token'];
//         if (!refreshToken) {
//           // in this case, redirect to login or home page
//           return res.status(401).json({ message: 'Unauthorized: No refresh token provided' });
//         }
//         // Verify refresh token
//         jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
//           if (err) {
//             // in this case, redirect to login or home page
//             return res.status(403).json({ message: 'Unauthorized: Invalid refresh token' });
//           } else {
//             // Refresh token is valid, issue a new access token
//             const role =  admins.some(u => u.id === decoded.sub) ? "admin" : "user";
//             const newAccessToken = jwt.sign(
//               { 
//                 sub: decoded.sub,
//                 iat: Math.floor(Date.now() / 1000),
//                 role: role
//               },
//               process.env.ACCESS_TOKEN_SECRET,
//               { expiresIn: '15m' }
//             );
//             req.user = { id: decoded.sub, role: role }; // id, role
//             const isValid = allowedRoles.some(role => role === req.user.role);
//             if(!isValid) return res.sendStatus(401);
//             return res.status(200).json({ accessToken: newAccessToken });
//           }
//         });
//       }
//       req.user=user; // id, role
//       const isValid = allowedRoles.some(role => role === req.user.role);
//       if(!isValid) return res.sendStatus(401);
//       next();
//     })(req, res, next);
//   }
// }
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



// Routes
app.post('/api/v1/login', async (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).send('No username or password provided');
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT id, password FROM users WHERE username = $1', [username]);
    if (result.rows.length) {
      // user exist
      const { id: userId, password: storedPassword } = result.rows[0];
      const role = admins.some(u => u.id === userId) ? "admin" : "user";
      if(bcrypt.compareSync(password, storedPassword)){
        // user logged in
        const refreshToken = jwt.sign(
          {
            sub: userId,
            iat: Math.floor(Date.now() / 1000), // in seconds
            role: role
          },
          process.env.REFRESH_TOKEN_SECRET,
          { expiresIn: "1h" }
        );
        const accessToken = jwt.sign(
          {
            sub: userId,
            iat: Math.floor(Date.now() / 1000), // in seconds
            role: role
          },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "15m" }
        );
        res.cookie("refresh-token", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          maxAge: 3600000, // in milliseconds
        });
        console.log("Login successful");
        return res.status(200).json({ accessToken, role });
      }else{
        // incorrect password
        return res.status(401).json({ message: 'Incorrect password' });
      }
    }else{
      // user not found 
      return res.status(401).json({ message: 'User not found' });
    }
  } catch (error) {
    // backend screwed up
    console.log(error.stack);
    res.status(500).json({ message: 'Internal server error' });
  }finally{
    if (client) {
      client.release();
    }
  }
});

app.post('/api/v1/register', async (req, res) => {
  const { username, email, password } = req.body;
  if(!username || !password || !email) return res.status(400).send('No username or email or password provided');
  const client = await pool.connect();
  try{
    const result = await client.query('SELECT id FROM users WHERE username = $1 or email=$2', [username, email]);
    if(result.rows.length){
      // user already exists
      return res.status(409).json({ message: "try again with a different username or email." });
    }else{
      // user registered
      const hashedPassword = bcrypt.hashSync(password, saltRounds);
      const response = await client.query(
        `INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id;`,
        [username, email, hashedPassword]
      );
      const { id: userId } = response.rows[0];
      const role = admins.some(u => u.id === userId) ? "admin" : "user";
      const refreshToken = jwt.sign(
        {
          sub: userId,
          iat: Math.floor(Date.now() / 1000),
          role: role
        },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "1h" }
      );
      const accessToken = jwt.sign(
        {
          sub: userId,
          iat: Math.floor(Date.now() / 1000),
          role: role
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
      );
      res.cookie("refresh-token", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 3600000,
      });
      console.log("Registeration successful");
      return res.status(200).json({ accessToken, role });
    }
  }catch(error){
    // backend screwed up
    console.log(error.stack);
    res.status(500).json({ message: 'Internal server error' });
  }finally{
    if (client) {
      client.release(); 
    }
  }
});

app.get('/api/v1/logout', async (req, res)=>{
  if(!req.cookies?.["refresh-token"]) return res.sendStatus(204) // No Content
  res.clearCookie("refresh-token", { httpOnly: true, secure: process.env.NODE_ENV === "production" });
  res.status(200).send("successfully, logged out");
});


// first implementation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
app.use(authenticateJWT);
app.use(handleNewAccessToken);

app.get('/api/v1/protected/admin/dashboard', verifyRoles("admin") ,async (req, res)=>{
  return res.status(200).json({ message: "welcome, admin" })
});

app.get('/api/v1/protected/user/profile', verifyRoles("user"), async (req, res)=>{
    return res.status(200).json({ message: "welcome, user" })
});
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


// second implementation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// app.get('/api/v1/protected/admin/dashboard', authenticate("admin") ,async (req, res)=>{
//   return res.status(200).json({ message: "welcome, admin" })
// });

// app.get('/api/v1/protected/user/profile', authenticate("user"), async (req, res)=>{
//     return res.status(200).json({ message: "welcome, user" })
// });
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


app.listen(PORT, ()=> console.log(`server is running at http://localhost:${PORT}`))
