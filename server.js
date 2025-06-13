const express = require("express")
const dotenv = require("dotenv")
const bcrypt = require("bcrypt")
const jsonwebtoken = require("jsonwebtoken")
const joi = require("joi")
const cors = require("cors")
const connectDatabase = require("./src/database/connect")
const UserModel = require("./src/models/user.model")

dotenv.config()
connectDatabase()
const app = express()
const PORT = process.env.PORT
const allowedOrigins = [
  process.env.FRONT_URL,
  process.env.SPRING_URL
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
}));

app.use(express.json())

function authMiddleware(req, res, next) {
    let token = req.headers.cookie
    token = token.split('=')[1]
    if (!token) return res.status(400).send("no token specified")
    try {
        req.user = jsonwebtoken.verify(token, process.env.SECRET)
        next()
    } catch (error) {res.status(401).send("invalid token")}
}

function validateUser(req, res, next) {
    const schema = joi.object({
        username: joi.string().min(1).max(64).pattern(/^[a-zA-Z ]*$/),
        email: joi.string().email().min(5).max(320),
        password: joi.string().min(8).max(32)
    })
    if (Object.keys(req.body).length == 0) {
        return res.status(400).json({error:"empty json"})
    }
    const validation = schema.validate(req.body)
    if (validation.error) {
        return res.status(400).json({error: validation.error.details[0].message})
    }
    next()
}

app.get("/", (req, res) => {
    res.send("RESTaurante API v1.0")
})

app.post("/register", validateUser, async (req, res) => {
    let username = req.body.username
    let password = req.body.password
    let email = req.body.email
    if(!email || !password || !username) return res.status(400).send("missing property")
    if (await UserModel.findOne({email})) return res.status(400).send("existing user")
    password = await bcrypt.hash(password, 10)
    await UserModel.create({username, password, email})
    res.sendStatus(200)
})

app.post("/login", async (req, res) => {
    const email = req.body.email
    const password = req.body.password
    const user = await UserModel.findOne({email})
    if (!user || !password) return res.status(400).send("login error")
    if (!await bcrypt.compare(password, user.password)) return res.status(401).send("wrong password")
    const payload = {username: user.username, email: user.email}
    const token = jsonwebtoken.sign(payload, process.env.SECRET)
    res.cookie("token", token)
    res.sendStatus(200)
})

// protected routes
app.use(authMiddleware)

app.get("/users/me", async (req, res) => {
    if (req.headers["x-api-key"] != process.env.API_KEY) return res.sendStatus(403)
    const user = await UserModel.findOne({email:req.user.email})
    if (!user) return res.sendStatus(404)
    res.json({username: user.username, email: user.email, id: user._id})
})

app.delete("/users/me", async (req, res) => {
    await UserModel.findOneAndDelete({email:req.user.email})
    res.sendStatus(200)
})

app.patch("/users/me", validateUser, async (req, res) => {
    // update password
    let password = req.body.password
    if (!password) return res.status(400).send("no password specified")
    password = await bcrypt.hash(password, 10)
    await UserModel.findOneAndUpdate({email:req.user.email}, {password})
    res.sendStatus(200)
})

app.use ((error, req, res, next) => {res.sendStatus(500); console.log(error)})

app.listen(PORT, () => console.log("server running on:", PORT))
