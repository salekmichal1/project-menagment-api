import express from "express";
import jwt from "jsonwebtoken";
import "dotenv/config";
import cors from "cors";
import { get } from "http";

const app = express();
const port = 3000;

//////////////////////
// connect to firebase

const admin = require("firebase-admin");
const serviceAccount = require("./managme-database-firebase-adminsdk-j9dgs-3792624515.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

//////////////////////

const tokenSecret = process.env.TOKEN_SECRET as string;
let refreshToken: string;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send({ message: "Hello World!" });
});

app.post("/token", function (req, res) {
  const expTime = req.body.exp || 60;
  const token = generateToken(+expTime);
  refreshToken = generateToken(60 * 60);
  res.status(200).send({ token, refreshToken });
});

app.post("/refreshToken", function (req, res) {
  const refreshTokenFromPost = req.body.refreshToken;

  if (refreshToken !== refreshTokenFromPost) {
    res.status(400).send("Bad refresh token!");
  } else {
    const expTime = req.headers.exp || 60;
    // const token = generateToken(+expTime);
    // refreshToken = generateToken(60 * 60);
    // setTimeout(() => {
    //   res.status(200).send({ token, refreshToken });
    // }, 3000);
    jwt.verify(refreshToken, tokenSecret, (err, user) => {
      if (err) {
        return res.status(403).send({ message: "Invalid refresh token" });
      }
      console.log(user);
      // Fetch the user data from the database
      // db.collection("Users")
      //   .doc((user as { id: string }).id)
      //   .get()
      //   .then((doc: any) => {
      //     if (!doc.exists) {
      //       return res.status(404).send({ message: "User not found" });
      //     }

      //     const userData = doc.data();
      //     delete userData.password; // Don't send the password back to the client

      //     res.status(200).send({ user: userData });
      //   })
      //   .catch((error: any) => {
      //     console.error("Error fetching user data:", error);
      //     res.status(500).send({ message: "Error fetching user data" });
      //   });
    });
  }
});

// app.post('/refresh-token', (req, res) => {
//   const refreshToken = req.body.refreshToken;

//   if (!refreshToken) {
//     return res.status(403).send({ message: 'No refresh token provided' });
//   }

//   jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
//     if (err) {
//       return res.status(403).send({ message: 'Invalid refresh token' });
//     }

//     // Fetch the user data from the database
//     db.collection('Users').doc(user.id).get()
//       .then((doc) => {
//         if (!doc.exists) {
//           return res.status(404).send({ message: 'User not found' });
//         }

//         const userData = doc.data();
//         delete userData.password; // Don't send the password back to the client

//         const newAccessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60s' });
//         res.status(200).send({ accessToken: newAccessToken, user: userData });
//       })
//       .catch((error) => {
//         console.error('Error fetching user data:', error);
//         res.status(500).send({ message: 'Error fetching user data' });
//       });
//   });
// });

app.get("/protected/:id/:delay?", verifyToken, (req, res) => {
  const id = req.params.id;
  const delay = req.params.delay ? +req.params.delay : 1000;
  setTimeout(() => {
    res.status(200).send(`{"message": "protected endpoint ${id}"}`);
  }, delay);
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  db.collection("Users")
    .get()
    .then((snapshot: any) => {
      let userFound: boolean = false;
      // const users: any[] = [];
      snapshot.forEach((doc: any) => {
        // users.push(doc.data());
        if (
          doc.data().username === username &&
          doc.data().password === password
        ) {
          userFound = true;
          const user = doc.data();
          user.id = doc.id;
          delete user.password;
          const token = generateToken(60, user);
          refreshToken = generateToken(60 * 60, user);
          res.status(200).send({ token, refreshToken, user });
        }
      });

      if (!userFound) {
        res.status(400).send({ message: "Bad username or password!" });
      }
    })
    .catch((error: any) => {
      console.log("Error getting users:", error);
      res.status(500).send("Error getting users");
    });
});

app.delete("/logout", (req, res) => {
  if (refreshToken === req.body.refreshToken) {
    refreshToken = "";
    res.status(200).send({ message: "Logged out!" });
  } else {
    res.status(400).send({ message: "Bad refresh token!" });
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

function generateToken(expirationInSeconds: number, user?: any) {
  const exp = Math.floor(Date.now() / 1000) + expirationInSeconds;
  const token = jwt.sign({ exp, user }, tokenSecret, {
    algorithm: "HS256",
  });
  return token;
}

function verifyToken(req: any, res: any, next: any) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token) return res.sendStatus(403);

  jwt.verify(token, tokenSecret, (err: any, user: any) => {
    if (err) {
      console.log(err);
      return res.status(401).send(err.message);
    }
    req.user = user;
    next();
  });
}
