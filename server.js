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

app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

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
    mongoose.connect(MONGODB_URI)
        .then(() => {
            console.log("✅ CELDEX MongoDB connected");
        })
        .catch((err) => {
            console.error("❌ MongoDB error:", err);
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
        default: "offline"
    },

    authToken: {
        type: String,
        default: ""
    }

}, {
    timestamps: true
});

const User = mongoose.model("User", userSchema);

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
    }],

    isPrivate: {
        type: Boolean,
        default: false
    }

}, {
    timestamps: true
});

const Channel = mongoose.model("Channel", channelSchema);

/* =====================================================
   CHANNEL INVITE SCHEMA
===================================================== */

const channelInviteSchema = new mongoose.Schema({

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

}, {
    timestamps: true
});

const ChannelInvite = mongoose.model(
    "ChannelInvite",
    channelInviteSchema
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

const Message = mongoose.model("Message", messageSchema);

/* =====================================================
   AUTHENTICATION
===================================================== */

async function authenticate(req, res, next) {

    try {

        const header = req.headers.authorization;

        if (!header || !header.startsWith("Bearer ")) {
            return res.status(401).json({
                error: "Authentication required"
            });
        }

        const token = header.substring(7);

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

        res.status(500).json({
            error: "Authentication error"
        });
    }
}

/* =====================================================
   TEST
===================================================== */

app.get("/", (req, res) => {

    res.json({
        name: "CELDEX",
        status: "online",
        version: "2.0.0"
    });

});

/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", async (req, res) => {

    try {

        let { username, password } = req.body;

        username = username?.trim().toLowerCase();

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

        const hashedPassword =
            await bcrypt.hash(password, 12);

        const token =
            crypto.randomBytes(48).toString("hex");

        const user = await User.create({

            username,

            password: hashedPassword,

            authToken: token,

            status: "online"

        });

        res.status(201).json({

            message: "Account created",

            token,

            user: {
                id: user._id,
                username: user.username,
                avatar: user.avatar
            }

        });

    } catch (error) {

        console.error("Register error:", error);

        res.status(500).json({
            error: "Registration failed"
        });
    }

});

/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", async (req, res) => {

    try {

        const username =
            req.body.username?.trim().toLowerCase();

        const password =
            req.body.password;

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

        const valid =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!valid) {
            return res.status(401).json({
                error: "Invalid username or password"
            });
        }

        const token =
            crypto.randomBytes(48).toString("hex");

        user.authToken = token;
        user.status = "online";

        await user.save();

        res.json({

            message: "Login successful",

            token,

            user: {
                id: user._id,
                username: user.username,
                avatar: user.avatar
            }

        });

    } catch (error) {

        console.error("Login error:", error);

        res.status(500).json({
            error: "Login failed"
        });
    }

});

/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", authenticate, async (req, res) => {

    res.json({

        id: req.user._id,
        username: req.user.username,
        avatar: req.user.avatar,
        status: req.user.status

    });

});

/* =====================================================
   USER SEARCH
===================================================== */

/*
   THIS FIXES THE SEARCH PROBLEM.

   Frontend can call:

   /api/users/search?q=username
*/

app.get("/api/users/search", authenticate, async (req, res) => {

    try {

        const q =
            String(req.query.q || "")
                .trim()
                .toLowerCase();

        if (!q) {
            return res.json([]);
        }

        if (q.length < 1) {
            return res.json([]);
        }

        const users = await User.find({
            username: {
                $regex: "^" + escapeRegex(q),
                $options: "i"
            },

            _id: {
                $ne: req.user._id
            }

        })
        .select("_id username avatar status")
        .limit(20);

        res.json(users);

    } catch (error) {

        console.error("User search error:", error);

        res.status(500).json({
            error: "User search failed"
        });

    }

});

/* =====================================================
   REGEX ESCAPE
===================================================== */

function escapeRegex(text) {

    return text.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
    );

}

/* =====================================================
   UPDATE AVATAR
===================================================== */

app.put("/api/avatar", authenticate, async (req, res) => {

    try {

        const { avatar } = req.body;

        if (typeof avatar !== "string") {
            return res.status(400).json({
                error: "Invalid avatar"
            });
        }

        req.user.avatar =
            avatar.substring(0, 500);

        await req.user.save();

        res.json({

            message: "Avatar updated",

            avatar: req.user.avatar

        });

    } catch (error) {

        console.error("Avatar error:", error);

        res.status(500).json({
            error: "Could not update avatar"
        });

    }

});

/* =====================================================
   CREATE CHANNEL
===================================================== */

app.post("/api/channels", authenticate, async (req, res) => {

    try {

        const name =
            req.body.name?.trim();

        const isPrivate =
            Boolean(req.body.isPrivate);

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

            members: [
                req.user._id
            ],

            isPrivate

        });

        res.status(201).json(channel);

    } catch (error) {

        console.error("Create channel error:", error);

        res.status(500).json({
            error: "Could not create channel"
        });

    }

});

/* =====================================================
   GET CHANNELS
===================================================== */

app.get("/api/channels", authenticate, async (req, res) => {

    try {

        const channels = await Channel.find({

            members: req.user._id

        })
        .populate("owner", "username avatar")
        .sort({
            createdAt: 1
        });

        res.json(channels);

    } catch (error) {

        console.error("Get channels error:", error);

        res.status(500).json({
            error: "Could not load channels"
        });

    }

});

/* =====================================================
   GET CHANNEL
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
                .populate("owner", "username avatar")
                .populate(
                    "members",
                    "username avatar status"
                );

            if (!channel) {
                return res.status(404).json({
                    error: "Channel not found"
                });
            }

            res.json(channel);

        } catch (error) {

            console.error(error);

            res.status(500).json({
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

            const { username } = req.body;

            const channel =
                await Channel.findOne({
                    _id: req.params.channelId
                });

            if (!channel) {
                return res.status(404).json({
                    error: "Channel not found"
                });
            }

            /* ONLY OWNER CAN INVITE */

            if (
                channel.owner.toString() !==
                req.user._id.toString()
            ) {

                return res.status(403).json({
                    error: "Only the channel owner can invite people"
                });

            }

            const user =
                await User.findOne({
                    username:
                        username?.trim().toLowerCase()
                });

            if (!user) {
                return res.status(404).json({
                    error: "User not found"
                });
            }

            if (
                user._id.toString() ===
                req.user._id.toString()
            ) {

                return res.status(400).json({
                    error: "You are already the owner"
                });

            }

            const alreadyMember =
                channel.members.some(
                    member =>
                        member.toString() ===
                        user._id.toString()
                );

            if (alreadyMember) {
                return res.status(400).json({
                    error: "User is already in this channel"
                });
            }

            const existingInvite =
                await ChannelInvite.findOne({
                    channel: channel._id,
                    invitedUser: user._id,
                    status: "pending"
                });

            if (existingInvite) {
                return res.status(400).json({
                    error: "Invitation already sent"
                });
            }

            const invite =
                await ChannelInvite.create({

                    channel: channel._id,

                    inviter: req.user._id,

                    invitedUser: user._id

                });

            res.status(201).json({

                message: "Invitation sent",

                invite: {
                    id: invite._id,
                    channel: channel._id,
                    username: user.username
                }

            });

        } catch (error) {

            console.error("Invite error:", error);

            res.status(500).json({
                error: "Could not invite user"
            });

        }

    }
);

/* =====================================================
   GET MY CHANNEL INVITES
===================================================== */

app.get(
    "/api/channel-invites",
    authenticate,
    async (req, res) => {

        try {

            const invites =
                await ChannelInvite.find({

                    invitedUser: req.user._id,

                    status: "pending"

                })
                .populate(
                    "channel",
                    "name isPrivate owner"
                )
                .populate(
                    "inviter",
                    "username avatar"
                )
                .sort({
                    createdAt: -1
                });

            res.json(invites);

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Could not load invitations"
            });

        }

    }
);

/* =====================================================
   ACCEPT CHANNEL INVITE
===================================================== */

app.post(
    "/api/channel-invites/:inviteId/accept",
    authenticate,
    async (req, res) => {

        try {

            const invite =
                await ChannelInvite.findOne({
                    _id: req.params.inviteId,

                    invitedUser: req.user._id,

                    status: "pending"

                });

            if (!invite) {
                return res.status(404).json({
                    error: "Invitation not found"
                });
            }

            const channel =
                await Channel.findById(
                    invite.channel
                );

            if (!channel) {

                invite.status = "declined";

                await invite.save();

                return res.status(404).json({
                    error: "Channel no longer exists"
                });

            }

            const alreadyMember =
                channel.members.some(
                    member =>
                        member.toString() ===
                        req.user._id.toString()
                );

            if (!alreadyMember) {

                channel.members.push(
                    req.user._id
                );

                await channel.save();

            }

            invite.status = "accepted";

            await invite.save();

            res.json({

                message: "Joined channel",

                channel

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Could not accept invitation"
            });

        }

    }
);

/* =====================================================
   DECLINE CHANNEL INVITE
===================================================== */

app.post(
    "/api/channel-invites/:inviteId/decline",
    authenticate,
    async (req, res) => {

        try {

            const invite =
                await ChannelInvite.findOne({
                    _id: req.params.inviteId,

                    invitedUser: req.user._id,

                    status: "pending"

                });

            if (!invite) {
                return res.status(404).json({
                    error: "Invitation not found"
                });
            }

            invite.status = "declined";

            await invite.save();

            res.json({
                message: "Invitation declined"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Could not decline invitation"
            });

        }

    }
);

/* =====================================================
   REMOVE MEMBER
===================================================== */

app.delete(
    "/api/channels/:channelId/members/:userId",
    authenticate,
    async (req, res) => {

        try {

            const channel =
                await Channel.findById(
                    req.params.channelId
                );

            if (!channel) {
                return res.status(404).json({
                    error: "Channel not found"
                });
            }

            /* OWNER ONLY */

            if (
                channel.owner.toString() !==
                req.user._id.toString()
            ) {

                return res.status(403).json({
                    error: "Only the channel owner can remove members"
                });

            }

            /* OWNER CANNOT REMOVE THEMSELVES */

            if (
                req.params.userId ===
                channel.owner.toString()
            ) {

                return res.status(400).json({
                    error: "Owner cannot be removed"
                });

            }

            const wasMember =
                channel.members.some(
                    member =>
                        member.toString() ===
                        req.params.userId
                );

            if (!wasMember) {
                return res.status(404).json({
                    error: "User is not a member"
                });
            }

            channel.members =
                channel.members.filter(
                    member =>
                        member.toString() !==
                        req.params.userId
                );

            await channel.save();

            res.json({
                message: "Member removed"
            });

        } catch (error) {

            console.error("Remove member error:", error);

            res.status(500).json({
                error: "Could not remove member"
            });

        }

    }
);

/* =====================================================
   LEAVE CHANNEL
===================================================== */

app.post(
    "/api/channels/:channelId/leave",
    authenticate,
    async (req, res) => {

        try {

            const channel =
                await Channel.findById(
                    req.params.channelId
                );

            if (!channel) {
                return res.status(404).json({
                    error: "Channel not found"
                });
            }

            /* OWNER CANNOT LEAVE */

            if (
                channel.owner.toString() ===
                req.user._id.toString()
            ) {

                return res.status(400).json({
                    error:
                        "Channel owner cannot leave. Delete or transfer the channel first."
                });

            }

            channel.members =
                channel.members.filter(
                    member =>
                        member.toString() !==
                        req.user._id.toString()
                );

            await channel.save();

            res.json({
                message: "You left the channel"
            });

        } catch (error) {

            console.error("Leave channel error:", error);

            res.status(500).json({
                error: "Could not leave channel"
            });

        }

    }
);

/* =====================================================
   CHANNEL MESSAGES
===================================================== */

app.get(
    "/api/channels/:channelId/messages",
    authenticate,
    async (req, res) => {

        try {

            const channel =
                await Channel.findOne({
                    _id: req.params.channelId,

                    members: req.user._id

                });

            if (!channel) {
                return res.status(403).json({
                    error: "You are not a member of this channel"
                });
            }

            const messages =
                await Message.find({
                    channel: channel._id
                })
                .populate(
                    "sender",
                    "username avatar"
                )
                .sort({
                    createdAt: 1
                })
                .limit(100);

            res.json(messages);

        } catch (error) {

            console.error("Messages error:", error);

            res.status(500).json({
                error: "Could not load messages"
            });

        }

    }
);

/* =====================================================
   SOCKET AUTH
===================================================== */

io.use(async (socket, next) => {

    try {

        const token =
            socket.handshake.auth?.token;

        if (!token) {
            return next(
                new Error("Authentication required")
            );
        }

        const user =
            await User.findOne({
                authToken: token
            });

        if (!user) {
            return next(
                new Error("Invalid authentication")
            );
        }

        socket.user = user;

        next();

    } catch (error) {

        console.error(error);

        next(error);

    }

});

/* =====================================================
   SOCKET CONNECTION
===================================================== */

io.on("connection", async (socket) => {

    const user = socket.user;

    console.log(
        `🟢 ${user.username} connected`
    );

    user.status = "online";

    await user.save();

    /* =================================================
       JOIN CHANNEL
    ================================================= */

    socket.on(
        "joinChannel",
        async (channelId) => {

            try {

                const channel =
                    await Channel.findOne({

                        _id: channelId,

                        members: user._id

                    });

                if (!channel) {
                    return;
                }

                socket.join(
                    `channel:${channelId}`
                );

            } catch (error) {

                console.error(
                    "Join channel error:",
                    error
                );

            }

        }
    );

    /* =================================================
       SEND MESSAGE
    ================================================= */

    socket.on(
        "sendMessage",
        async (data) => {

            try {

                const {
                    channelId,
                    text
                } = data;

                if (
                    !channelId ||
                    !text ||
                    !String(text).trim()
                ) {
                    return;
                }

                const channel =
                    await Channel.findOne({

                        _id: channelId,

                        members: user._id

                    });

                if (!channel) {
                    return;
                }

                const message =
                    await Message.create({

                        sender: user._id,

                        channel: channel._id,

                        text:
                            String(text)
                                .trim()
                                .substring(0, 2000)

                    });

                const fullMessage =
                    await Message
                        .findById(message._id)
                        .populate(
                            "sender",
                            "username avatar"
                        );

                io.to(
                    `channel:${channelId}`
                ).emit(
                    "newMessage",
                    fullMessage
                );

            } catch (error) {

                console.error(
                    "Message error:",
                    error
                );

            }

        }
    );

    /* =================================================
       VOICE JOIN
    ================================================= */

    socket.on(
        "voiceJoin",
        (roomId) => {

            if (!roomId) return;

            socket.join(
                `voice:${roomId}`
            );

            socket.to(
                `voice:${roomId}`
            ).emit(
                "voiceUserJoined",
                {
                    userId:
                        user._id.toString(),

                    username:
                        user.username
                }
            );

        }
    );

    /* =================================================
       VOICE SIGNAL
    ================================================= */

    socket.on(
        "voiceSignal",
        (data) => {

            if (!data?.roomId) return;

            socket.to(
                `voice:${data.roomId}`
            ).emit(
                "voiceSignal",
                {
                    from: socket.id,

                    signal: data.signal
                }
            );

        }
    );

    /* =================================================
       VOICE LEAVE
    ================================================= */

    socket.on(
        "voiceLeave",
        (roomId) => {

            if (!roomId) return;

            socket.leave(
                `voice:${roomId}`
            );

            socket.to(
                `voice:${roomId}`
            ).emit(
                "voiceUserLeft",
                {
                    userId:
                        user._id.toString()
                }
            );

        }
    );

    /* =================================================
       DISCONNECT
    ================================================= */

    socket.on(
        "disconnect",
        async () => {

            console.log(
                `🔴 ${user.username} disconnected`
            );

            try {

                user.status = "offline";

                await user.save();

            } catch (error) {

                console.error(
                    "Disconnect error:",
                    error
                );

            }

        }
    );

});

/* =====================================================
   SERVER
===================================================== */

const PORT =
    process.env.PORT || 3000;

server.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `🚀 CELDEX server running on port ${PORT}`
        );

    }
);
