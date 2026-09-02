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
   CORS
===================================================== */

app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"]
    })
);

app.use(express.json({ limit: "1mb" }));

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

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error("❌ MONGODB_URI is missing!");
} else {
    mongoose
        .connect(MONGODB_URI)
        .then(() => {
            console.log("✅ CELDEX MongoDB connected");
        })
        .catch((error) => {
            console.error("❌ MongoDB error:", error);
        });
}

/* =====================================================
   USER SCHEMA
===================================================== */

const userSchema = new mongoose.Schema(
    {
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
            default: "",
            index: true
        }
    },
    {
        timestamps: true
    }
);

const User = mongoose.model("User", userSchema);

/* =====================================================
   CHANNEL SCHEMA
===================================================== */

const channelSchema = new mongoose.Schema(
    {
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

        members: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User"
            }
        ],

        isPrivate: {
            type: Boolean,
            default: false
        }
    },
    {
        timestamps: true
    }
);

const Channel = mongoose.model("Channel", channelSchema);

/* =====================================================
   CHANNEL INVITE SCHEMA
===================================================== */

const channelInviteSchema = new mongoose.Schema(
    {
        channel: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Channel",
            required: true
        },

        inviter: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        invitedUser: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        status: {
            type: String,
            enum: ["pending", "accepted", "declined"],
            default: "pending"
        }
    },
    {
        timestamps: true
    }
);

const ChannelInvite = mongoose.model(
    "ChannelInvite",
    channelInviteSchema
);

/* =====================================================
   MESSAGE SCHEMA
===================================================== */

const messageSchema = new mongoose.Schema(
    {
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

        dmUsers: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User"
            }
        ],

        text: {
            type: String,
            required: true,
            maxlength: 2000,
            trim: true
        }
    },
    {
        timestamps: true
    }
);

const Message = mongoose.model("Message", messageSchema);

/* =====================================================
   HELPERS
===================================================== */

function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isMember(channel, userId) {
    return channel.members.some(
        (member) => member.toString() === userId.toString()
    );
}

function isOwner(channel, userId) {
    return (
        channel.owner.toString() === userId.toString()
    );
}

/* =====================================================
   AUTHENTICATION MIDDLEWARE
===================================================== */

async function authenticate(req, res, next) {
    try {
        const header = req.headers.authorization;

        if (!header || !header.startsWith("Bearer ")) {
            return res.status(401).json({
                error: "Authentication required"
            });
        }

        const token = header.substring(7).trim();

        if (!token) {
            return res.status(401).json({
                error: "Authentication required"
            });
        }

        const user = await User.findOne({
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
        console.error("Authentication error:", error);

        return res.status(500).json({
            error: "Authentication error"
        });
    }
}

/* =====================================================
   HEALTH CHECK
===================================================== */

app.get("/", (req, res) => {
    res.json({
        name: "CELDEX",
        status: "online",
        version: "3.0.0"
    });
});

/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", async (req, res) => {
    try {
        let { username, password } = req.body;

        username = String(username || "")
            .trim()
            .toLowerCase();

        password = String(password || "");

        if (!username || !password) {
            return res.status(400).json({
                error: "Username and password are required"
            });
        }

        if (username.length < 3 || username.length > 24) {
            return res.status(400).json({
                error: "Username must be 3-24 characters"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error: "Password must be at least 6 characters"
            });
        }

        const existingUser = await User.findOne({
            username
        });

        if (existingUser) {
            return res.status(409).json({
                error: "Username already exists"
            });
        }

        const hashedPassword = await bcrypt.hash(
            password,
            12
        );

        const token = crypto
            .randomBytes(48)
            .toString("hex");

        const user = await User.create({
            username,
            password: hashedPassword,
            authToken: token,
            status: "online"
        });

        return res.status(201).json({
            message: "Account created",

            token,

            user: {
                id: user._id,
                username: user.username,
                avatar: user.avatar,
                status: user.status
            }
        });
    } catch (error) {
        console.error("Register error:", error);

        return res.status(500).json({
            error: "Registration failed"
        });
    }
});

/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", async (req, res) => {
    try {
        const username = String(
            req.body.username || ""
        )
            .trim()
            .toLowerCase();

        const password = String(
            req.body.password || ""
        );

        if (!username || !password) {
            return res.status(400).json({
                error: "Username and password are required"
            });
        }

        const user = await User.findOne({
            username
        });

        if (!user) {
            return res.status(401).json({
                error: "Invalid username or password"
            });
        }

        const validPassword = await bcrypt.compare(
            password,
            user.password
        );

        if (!validPassword) {
            return res.status(401).json({
                error: "Invalid username or password"
            });
        }

        const token = crypto
            .randomBytes(48)
            .toString("hex");

        user.authToken = token;
        user.status = "online";

        await user.save();

        return res.json({
            message: "Login successful",

            token,

            user: {
                id: user._id,
                username: user.username,
                avatar: user.avatar,
                status: user.status
            }
        });
    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            error: "Login failed"
        });
    }
});

/* =====================================================
   LOGOUT
===================================================== */

app.post("/api/logout", authenticate, async (req, res) => {
    try {
        req.user.authToken = "";
        req.user.status = "offline";

        await req.user.save();

        return res.json({
            message: "Logged out successfully"
        });
    } catch (error) {
        console.error("Logout error:", error);

        return res.status(500).json({
            error: "Logout failed"
        });
    }
});

/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", authenticate, async (req, res) => {
    return res.json({
        id: req.user._id,
        username: req.user.username,
        avatar: req.user.avatar,
        status: req.user.status
    });
});

/* =====================================================
   USER SEARCH
===================================================== */

app.get(
    "/api/users/search",
    authenticate,
    async (req, res) => {
        try {
            const q = String(req.query.q || "")
                .trim()
                .toLowerCase();

            if (!q) {
                return res.json([]);
            }

            const safeQuery = escapeRegex(q);

            const users = await User.find({
                username: {
                    $regex: safeQuery,
                    $options: "i"
                },

                _id: {
                    $ne: req.user._id
                }
            })
                .select("_id username avatar status")
                .sort({
                    username: 1
                })
                .limit(20);

            return res.json(users);
        } catch (error) {
            console.error(
                "User search error:",
                error
            );

            return res.status(500).json({
                error: "User search failed"
            });
        }
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
            const { avatar } = req.body;

            if (typeof avatar !== "string") {
                return res.status(400).json({
                    error: "Invalid avatar"
                });
            }

            req.user.avatar = avatar.substring(
                0,
                500
            );

            await req.user.save();

            return res.json({
                message: "Avatar updated",
                avatar: req.user.avatar
            });
        } catch (error) {
            console.error(
                "Avatar error:",
                error
            );

            return res.status(500).json({
                error: "Could not update avatar"
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
            const name = String(
                req.body.name || ""
            ).trim();

            const isPrivate =
                req.body.isPrivate === true;

            if (!name) {
                return res.status(400).json({
                    error: "Channel name required"
                });
            }

            if (name.length > 50) {
                return res.status(400).json({
                    error: "Channel name is too long"
                });
            }

            const channel = await Channel.create({
                name,
                owner: req.user._id,
                members: [req.user._id],
                isPrivate
            });

            await channel.populate(
                "owner",
                "username avatar"
            );

            return res.status(201).json(channel);
        } catch (error) {
            console.error(
                "Create channel error:",
                error
            );

            return res.status(500).json({
                error: "Could not create channel"
            });
        }
    }
);

/* =====================================================
   GET MY CHANNELS
===================================================== */

app.get(
    "/api/channels",
    authenticate,
    async (req, res) => {
        try {
            const channels = await Channel.find({
                members: req.user._id
            })
                .populate(
                    "owner",
                    "username avatar"
                )
                .sort({
                    createdAt: 1
                });

            return res.json(channels);
        } catch (error) {
            console.error(
                "Get channels error:",
                error
            );

            return res.status(500).json({
                error: "Could not load channels"
            });
        }
    }
);

/* =====================================================
   GET SINGLE CHANNEL
===================================================== */

app.get(
    "/api/channels/:channelId",
    authenticate,
    async (req, res) => {
        try {
            const channel =
                await Channel.findOne({
                    _id: req.params.channelId,
                    members: req.user._id
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
                        "Channel not found or you are not a member"
                });
            }

            return res.json(channel);
        } catch (error) {
            console.error(
                "Get channel error:",
                error
            );

            return res.status(500).json({
                error: "Could not load channel"
            });
        }
    }
);

/* =====================================================
   INVITE USER TO CHANNEL
===================================================== */

app.post(
    "/api/channels/:channelId/invite",
    authenticate,
    async (req, res) => {
        try {
            const username = String(
                req.body.username || ""
            )
                .trim()
                .toLowerCase();

            if (!username) {
                return res.status(400).json({
                    error: "Username is required"
                });
            }

            const channel =
                await Channel.findById(
                    req.params.channelId
                );

            if (!channel) {
                return res.status(404).json({
                    error: "Channel not found"
                });
            }

            /*
             * ONLY THE OWNER CAN INVITE.
             */

            if (
                !isOwner(
                    channel,
                    req.user._id
                )
            ) {
                return res.status(403).json({
                    error:
                        "Only the channel owner can invite people"
                });
            }

            const invitedUser =
                await User.findOne({
                    username
                });

            if (!invitedUser) {
                return res.status(404).json({
                    error: "User not found"
                });
            }

            if (
                invitedUser._id.toString() ===
                req.user._id.toString()
            ) {
                return res.status(400).json({
                    error:
                        "You are already the channel owner"
                });
            }

            if (
                isMember(
                    channel,
                    invitedUser._id
                )
            ) {
                return res.status(400).json({
                    error:
                        "User is already in this channel"
                });
            }

            /*
             * Remove old declined/accepted invites
             * only when creating a fresh invitation.
             */

            const existingPendingInvite =
                await ChannelInvite.findOne({
                    channel: channel._id,
                    invitedUser: invitedUser._id,
                    status: "pending"
                });

            if (existingPendingInvite) {
                return res.status(400).json({
                    error:
                        "Invitation already sent"
                });
            }

            const invite =
                await ChannelInvite.create({
                    channel: channel._id,
                    inviter: req.user._id,
                    invitedUser: invitedUser._id,
                    status: "pending"
                });

            /*
             * Notify the invited user's sockets.
             */

            io.to(
                `user:${invitedUser._id}`
            ).emit(
                "channelInvite",
                {
                    inviteId: invite._id,
                    channelId: channel._id,
                    channelName: channel.name,
                    inviter: {
                        id: req.user._id,
                        username:
                            req.user.username,
                        avatar:
                            req.user.avatar
 
