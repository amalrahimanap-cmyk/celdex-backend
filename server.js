require("dotenv").config();

const express = require("express");
const http = require("http");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

/* =====================================================
   CONFIG
===================================================== */

app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({
    limit: "1mb"
}));

/* =====================================================
   SOCKET.IO
===================================================== */

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

/* =====================================================
   DATABASE
===================================================== */

if (!process.env.MONGODB_URI) {

    console.error(
        "❌ MONGODB_URI environment variable is missing"
    );

} else {

    mongoose.connect(process.env.MONGODB_URI)
        .then(() => {

            console.log(
                "✅ CELDEX MongoDB connected"
            );

        })
        .catch((error) => {

            console.error(
                "❌ MongoDB error:",
                error
            );

        });

}

/* =====================================================
   USER SCHEMA
===================================================== */

const userSchema = new mongoose.Schema({

    username: {
        type: String,
        required: true,
        unique: true,
        minlength: 3,
        maxlength: 24,
        trim: true,
        lowercase: true
    },

    password: {
        type: String,
        required: true
    },

    avatar: {
        type: String,
        default: ""
    },

    status: {
        type: String,
        enum: ["online", "offline"],
        default: "offline"
    },

    authToken: {
        type: String,
        default: ""
    }

}, {
    timestamps: true
});

const User = mongoose.model(
    "User",
    userSchema
);

/* =====================================================
   CHANNEL SCHEMA
===================================================== */

const channelSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true,
        maxlength: 50,
        trim: true
    },

    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },

    members: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }]

}, {
    timestamps: true
});

const Channel = mongoose.model(
    "Channel",
    channelSchema
);

/* =====================================================
   MESSAGE SCHEMA
===================================================== */

const messageSchema = new mongoose.Schema({

    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },

    channel: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Channel",
        default: null
    },

    dmUsers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }],

    text: {
        type: String,
        required: true,
        maxlength: 2000,
        trim: true
    }

}, {
    timestamps: true
});

const Message = mongoose.model(
    "Message",
    messageSchema
);

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

async function authenticate(req, res, next) {

    try {

        const header =
            req.headers.authorization;

        if (
            !header ||
            !header.startsWith("Bearer ")
        ) {

            return res.status(401).json({
                error: "Authentication required"
            });

        }

        const token =
            header.substring(7).trim();

        if (!token) {

            return res.status(401).json({
                error: "Authentication token missing"
            });

        }

        const user =
            await User.findOne({
                authToken: token
            });

        if (!user) {

            return res.status(401).json({
                error: "Invalid login session"
            });

        }

        req.user = user;

        next();

    } catch (error) {

        console.error(
            "Authentication error:",
            error
        );

        return res.status(500).json({
            error: "Authentication error"
        });

    }

}

/* =====================================================
   TEST / HEALTH
===================================================== */

app.get("/", (req, res) => {

    res.json({
        name: "CELDEX",
        status: "online",
        version: "1.1.0",
        message: "CELDEX backend is working"
    });

});

/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", async (req, res) => {

    try {

        let {
            username,
            password
        } = req.body;

        username =
            username?.trim().toLowerCase();

        if (!username || !password) {

            return res.status(400).json({
                error:
                    "Username and password are required"
            });

        }

        if (
            username.length < 3 ||
            username.length > 24
        ) {

            return res.status(400).json({
                error:
                    "Username must be 3-24 characters"
            });

        }

        if (password.length < 6) {

            return res.status(400).json({
                error:
                    "Password must be at least 6 characters"
            });

        }

        const existingUser =
            await User.findOne({
                username
            });

        if (existingUser) {

            return res.status(409).json({
                error:
                    "Username already exists"
            });

        }

        const hashedPassword =
            await bcrypt.hash(
                password,
                12
            );

        const token =
            crypto
                .randomBytes(48)
                .toString("hex");

        const user =
            await User.create({

                username,

                password:
                    hashedPassword,

                authToken:
                    token,

                status:
                    "online"

            });

        return res.status(201).json({

            message:
                "Account created",

            token,

            user: {

                id:
                    user._id,

                username:
                    user.username,

                avatar:
                    user.avatar

            }

        });

    } catch (error) {

        console.error(
            "Registration error:",
            error
        );

        if (error.code === 11000) {

            return res.status(409).json({
                error:
                    "Username already exists"
            });

        }

        return res.status(500).json({
            error:
                "Registration failed"
        });

    }

});

/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", async (req, res) => {

    try {

        const {
            username,
            password
        } = req.body;

        const cleanUsername =
            username?.trim().toLowerCase();

        if (
            !cleanUsername ||
            !password
        ) {

            return res.status(400).json({
                error:
                    "Username and password are required"
            });

        }

        const user =
            await User.findOne({
                username:
                    cleanUsername
            });

        if (!user) {

            return res.status(401).json({
                error:
                    "Invalid username or password"
            });

        }

        const valid =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!valid) {

            return res.status(401).json({
                error:
                    "Invalid username or password"
            });

        }

        const token =
            crypto
                .randomBytes(48)
                .toString("hex");

        user.authToken =
            token;

        user.status =
            "online";

        await user.save();

        return res.json({

            message:
                "Login successful",

            token,

            user: {

                id:
                    user._id,

                username:
                    user.username,

                avatar:
                    user.avatar

            }

        });

    } catch (error) {

        console.error(
            "Login error:",
            error
        );

        return res.status(500).json({
            error:
                "Login failed"
        });

    }

});

/* =====================================================
   LOGOUT
===================================================== */

app.post(
    "/api/logout",
    authenticate,
    async (req, res) => {

        try {

            req.user.authToken = "";
            req.user.status = "offline";

            await req.user.save();

            return res.json({
                message:
                    "Logged out successfully"
            });

        } catch (error) {

            console.error(
                "Logout error:",
                error
            );

            return res.status(500).json({
                error:
                    "Logout failed"
            });

        }

    }
);

/* =====================================================
   CURRENT USER
===================================================== */

app.get(
    "/api/me",
    authenticate,
    async (req, res) => {

        return res.json({

            id:
                req.user._id,

            username:
                req.user.username,

            avatar:
                req.user.avatar,

            status:
                req.user.status

        });

    }
);

/* =====================================================
   UPDATE AVATAR
===================================================== */

app.put(
    "/api/avatar",
    authenticate,
    async (req, res) => {

        try {

            const {
                avatar
            } = req.body;

            if (
                typeof avatar !== "string"
            ) {

                return res.status(400).json({
                    error:
                        "Invalid avatar"
                });

            }

            req.user.avatar =
                avatar
                    .trim()
                    .substring(0, 500);

            await req.user.save();

            return res.json({

                message:
                    "Avatar updated",

                avatar:
                    req.user.avatar

            });

        } catch (error) {

            console.error(
                "Avatar error:",
                error
            );

            return res.status(500).json({
                error:
                    "Could not update avatar"
            });

        }

    }
);

/* =====================================================
   SEARCH USERS
===================================================== */

app.get(
    "/api/users/search",
    authenticate,
    async (req, res) => {

        try {

            const q =
                String(
                    req.query.q || ""
                )
                .trim()
                .toLowerCase();

            if (!q) {

                return res.json([]);

            }

            if (q.length < 1) {

                return res.json([]);

            }

            const users =
                await User.find({

                    username: {
                        $regex: q,
                        $options: "i"
                    }

                })
                .select(
                    "_id username avatar status"
                )
                .limit(20);

            const filtered =
                users.filter(
                    user =>
                        user._id.toString() !==
                        req.user._id.toString()
                );

            return res.json(
                filtered
            );

        } catch (error) {

            console.error(
                "User search error:",
                error
            );

            return res.status(500).json({
                error:
                    "Could not search users"
            });

        }

    }
);

/* =====================================================
   CREATE CHANNEL
===================================================== */

app.post(
    "/api/channels",
    authenticate,
    async (req, res) => {

        try {

            const name =
                req.body.name
                    ?.trim();

            if (!name) {

                return res.status(400).json({
                    error:
                        "Channel name required"
                });

            }

            if (name.length > 50) {

                return res.status(400).json({
                    error:
                        "Channel name is too long"
                });

            }

            const channel =
                await Channel.create({

                    name,

                    owner:
                        req.user._id,

                    members: [
                        req.user._id
                    ]

                });

            return res.status(201).json(
                channel
            );

        } catch (error) {

            console.error(
                "Create channel error:",
                error
            );

            return res.status(500).json({
                error:
                    "Could not create channel"
            });

        }

    }
);

/* =====================================================
   GET CHANNELS
===================================================== */

app.get(
    "/api/channels",
    authenticate,
    async (req, res) => {

        try {

            const channels =
                await Channel.find({

                    members:
                        req.user._id

                })
                .populate(
                    "owner",
                    "username avatar"
                )
                .sort({
                    createdAt: 1
                });

            return res.json(
                channels
            );

        } catch (error) {

            console.error(
                "Get channels error:",
                error
            );

            return res.status(500).json({
                error:
                    "Could not load channels"
            });

        }

    }
);

/* =====================================================
   GET CHANNEL DETAILS
===================================================== */

app.get(
    "/api/channels/:channelId",
    authenticate,
    async (req, res) => {

        try {

            const channel =
                await Channel.findOne({

                    _id:
                        req.params.channelId,

                    members:
                        req.user._id

                })
                .populate(
                    "owner",
                    "username avatar"
                )
                .populate(
                    "members",
                    "username avatar status"
                );

            if (!channel) {

                return res.status(404).json({
                    error:
                        "Channel not found"
                });

            }

            return res.json(
                channel
            );

        } catch (error) {

            console.error(
                "Channel details error:",
                error
            );

            return res.status(500).json({
                error:
                    "Could not load channel"
            });

        }

    }
);

/* =====================================================
   INVITE / ADD USER TO CHANNEL
===================================================== */

app.post(
    "/api/channels/:channelId/members",
    authenticate,
    async (req, res) => {

        try {

            const {
                userId,
                username
            } = req.body;

            /* -----------------------------------------
               FIND CHANNEL
            ----------------------------------------- */

            const channel =
                await Channel.findById(
                    req.params.channelId
                );

            if (!channel) {

                return res.status(404).json({
                    error:
                        "Channel not found"
                });

            }

            /* -----------------------------------------
               ONLY OWNER CAN INVITE
            ----------------------------------------- */

            if (
                channel.owner.toString() !==
                req.user._id.toString()
            ) {

                return res.status(403).json({
                    error:
                        "Only the channel owner can invite people"
                });

            }

            /* -----------------------------------------
               FIND USER
            ----------------------------------------- */

            let targetUser = null;

            if (userId) {

                targetUser =
                    await User.findById(
                        userId
                    );

            } else if (username) {

                targetUser =
                    await User.findOne({

                        username:
                            String(username)
                                .trim()
                                .toLowerCase()

                    });

            }

            if (!targetUser) {

                return res.status(404).json({
                    error:
                        "User not found"
                });

            }

            /* -----------------------------------------
               DON'T INVITE YOURSELF
            ----------------------------------------- */

            if (
                targetUser._id.toString() ===
                req.user._id.toString()
            ) {

                return res.status(400).json({
                    error:
                        "You are already the channel owner"
                });

            }

            /* -----------------------------------------
               CHECK EXISTING MEMBER
            ----------------------------------------- */

            const alreadyMember =
                channel.members.some(
                    member =>
                        member.toString() ===
                        targetUser._id.toString()
                );

            if (alreadyMember) {

                return res.status(409).json({
                    error:
                        "User is already in this channel"
                });

            }

            /* -----------------------------------------
               ADD MEMBER
            ----------------------------------------- */

            channel.members.push(
                targetUser._id
            );

            await channel.save();

            /* -----------------------------------------
             
