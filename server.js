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

const PORT = process.env.PORT || 3000;

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

if (!process.env.MONGODB_URI) {
    console.error("❌ MONGODB_URI is missing!");
} else {

    mongoose.connect(process.env.MONGODB_URI)
        .then(() => {
            console.log("✅ CELDEX MongoDB connected");
        })
        .catch((error) => {
            console.error("❌ MongoDB error:", error);
        });

}

/* =====================================================
   USER MODEL
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

const User = mongoose.model("User", userSchema);

/* =====================================================
   CHANNEL MODEL
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
   MESSAGE MODEL
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
   HELPER
===================================================== */

function validObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}

/* =====================================================
   AUTH MIDDLEWARE
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

        return res.status(500).json({
            error: "Authentication error"
        });

    }

}

/* =====================================================
   CHANNEL MEMBER MIDDLEWARE
===================================================== */

async function authenticateChannelMember(req, res, next) {

    try {

        const channelId = req.params.channelId;

        if (!validObjectId(channelId)) {

            return res.status(400).json({
                error: "Invalid channel ID"
            });

        }

        const channel = await Channel.findOne({
            _id: channelId,
            members: req.user._id
        });

        if (!channel) {

            return res.status(403).json({
                error: "You are not a member of this channel"
            });

        }

        req.channel = channel;

        next();

    } catch (error) {

        console.error(error);

        return res.status(500).json({
            error: "Channel access error"
        });

    }

}

/* =====================================================
   CHANNEL OWNER MIDDLEWARE
===================================================== */

async function authenticateChannelOwner(req, res, next) {

    try {

        const channelId =
            req.params.channelId ||
            req.params.id;

        if (!validObjectId(channelId)) {

            return res.status(400).json({
                error: "Invalid channel ID"
            });

        }

        const channel = await Channel.findById(channelId);

        if (!channel) {

            return res.status(404).json({
                error: "Channel not found"
            });

        }

        if (
            channel.owner.toString() !==
            req.user._id.toString()
        ) {

            return res.status(403).json({
                error: "Only the channel owner can do this"
            });

        }

        req.channel = channel;

        next();

    } catch (error) {

        console.error(error);

        return res.status(500).json({
            error: "Permission check failed"
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
        version: "2.0.0"
    });

});

/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", async (req, res) => {

    try {

        let { username, password } = req.body;

        username = username?.trim();

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

        const normalizedUsername =
            username.toLowerCase();

        const existingUser =
            await User.findOne({
                username: normalizedUsername
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

            username: normalizedUsername,

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
                avatar: user.avatar
            }

        });

    } catch (error) {

        console.error("Registration error:", error);

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

        const { username, password } = req.body;

        if (!username || !password) {

            return res.status(400).json({
                error: "Username and password are required"
            });

        }

        const user =
            await User.findOne({
                username: username.toLowerCase()
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

        return res.json({

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

        return res.status(500).json({
            error: "Login failed"
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

        return res.json({

            message: "Avatar updated",

            avatar: req.user.avatar

        });

    } catch (error) {

        console.error(error);

        return res.status(500).json({
            error: "Could not update avatar"
        });

    }

});

/* =====================================================
   SEARCH USERS
===================================================== */

app.get("/api/users/search", authenticate, async (req, res) => {

    try {

        const query =
            String(req.query.username || "")
                .trim()
                .toLowerCase();

        if (!query) {

            return res.json([]);

        }

        const users =
            await User.find({

                username: {
                    $regex: query,
                    $options: "i"
                },

                _id: {
                    $ne: req.user._id
                }

            })
            .select("_id username avatar status")
            .limit(20);

        return res.json(users);

    } catch (error) {

        console.error(error);

        return res.status(500).json({
            error: "User search failed"
        });

    }

});

/* =====================================================
   CREATE CHANNEL
===================================================== */

app.post("/api/channels", authenticate, async (req, res) => {

    try {

        const name =
            String(req.body.name || "").trim();

        const isPrivate =
            Boolean(req.body.isPrivate);

        if (!name) {

            return res.status(400).json({
                error: "Channel name required"
            });

        }

        if (name.length > 50) {

            return res.status(400).json({
                error: "Channel name cannot exceed 50 characters"
            });

        }

        const channel =
            await Channel.create({

                name,

                owner: req.user._id,

                members: [
                    req.user._id
                ],

                isPrivate

            });

        const populated =
            await Channel.findById(channel._id)
                .populate("owner", "username avatar")
                .populate("members", "username avatar status");

        return res.status(201).json(populated);

    } catch (error) {

        console.error("Create channel error:", error);

        return res.status(500).json({
            error: "Could not create channel"
        });

    }

});

/* =====================================================
   GET CHANNELS
===================================================== */

app.get("/api/channels", authenticate, async (req, res) => {

    try {

        /*
         * IMPORTANT:
         *
         * Private channels are returned ONLY
         * when the current user is a member.
         *
         * Public channels are also returned here.
         */

        const channels =
            await Channel.find({

                $or: [

                    {
                        isPrivate: false
                    },

                    {
                        members: req.user._id
                    }

                ]

            })
            .populate("owner", "username avatar")
            .sort({
                createdAt: 1
            });

        return res.json(channels);

    } catch (error) {

        console.error("Get channels error:", error);

        return res.status(500).json({
            error: "Could not load channels"
        });

    }

});

/* =====================================================
   GET SINGLE CHANNEL
===================================================== */

app.get(
    "/api/channels/:channelId",
    authenticate,
    authenticateChannelMember,
    async (req, res) => {

        const channel =
            await Channel.findById(req.channel._id)
                .populate(
                    "owner",
                    "username avatar status"
                )
                .populate(
                    "members",
                    "username avatar status"
                );

        return res.json(channel);

    }
);

/* =====================================================
   GET CHANNEL MEMBERS
===================================================== */

app.get(
    "/api/channels/:channelId/members",
    authenticate,
    authenticateChannelMember,
    async (req, res) => {

        try {

            const channel =
                await Channel.findById(
                    req.channel._id
                )
                .populate(
                    "owner",
                    "username avatar status"
                )
                .populate(
                    "members",
                    "username avatar status"
                );

            return res.json({

                channelId: channel._id,

                owner: channel.owner,

                members: channel.members

            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                error: "Could not load members"
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
    authenticateChannelOwner,
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username || ""
                )
                .trim()
                .toLowerCase();

            if (!username) {

                return res.status(400).json({
                    error: "Username required"
                });

            }

            const user =
                await User.findOne({
                    username
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
                    error: "You are already the channel owner"
                });

            }

            const alreadyMember =
                req.channel.members.some(
                    member =>
                        member.toString() ===
                        user._id.toString()
                );

            if (alreadyMember) {

                return res.status(409).json({
                    error: "User is already a channel member"
                });

            }

            req.channel.members.push(user._id);

            await req.channel.save();

            const updated =
                await Channel.findById(
                    req.channel._id
                )
                .populate(
                    "owner",
                    "username avatar status"
                )
                .populate(
                    "members",
                    "username avatar status"
                );

            /*
             * Notify the invited user if online.
             */

            io.emit("channelUpdated", {
                channelId: req.channel._id.toString()
            });

            return res.json({

                message: "User invited successfully",

                channel: updated

            });

        } catch (error) {

            console.error("Invite error:", error);

            return res.status(500).json({
                error: "Could not invite user"
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
    authenticateChannelOwner,
    async (req, res) => {

        try {

            const userId =
                req.params.userId;

            if (!validObjectId(userId)) {

                return res.status(400).json({
                    error: "Invalid user ID"
                });

            }

            /*
             * Owner cannot remove themselves
             * through this endpoint.
             */

            if (
                userId ===
                req.channel.owner.toString()
            ) {

                return res.status(400).json({
                    error: "Owner cannot remove themselves"
                });

            }

            const memberExists =
                req.channel.members.some(
                    member =>
                        member.toString() === userId
                );

            if (!memberExists) {

                return res.status(404).json({
                    error: "User is not a channel member"
                });

            }

            req.channel.members =
                req.channel.members.filter(
                    member =>
                        member.toString() !== userId
                );

            await req.channel.save();

            io.emit("channelUpdated", {
                channelId: req.channel._id.toString()
            });

            return res.json({
                message: "Member removed"
            });

        } catch (error) {

            console.error("Remove member error:", error);

            return res.status(500).json({
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
    authenticateChannelMember,
    async (req, res) => {

        try {

            /*
             * Channel owner cannot leave.
             * They must delete the channel or
             * ownership transfer can be added later.
             */

            if (
                req.channel.owner.toString() ===
                req.user._id.toString()
            ) {

                return res.status(400).json({
                    error:
                        "Channel owner cannot leave. Delete the channel instead."
                });

            }

            req.channel.members =
                req.channel.members.filter(
                    member =>
                        member.toString() !==
                        req.user._id.toString()
                );

            await req.channel.save();

            io.emit("channelUpdated", {
                channelId: req.channel._id.toString()
            });

            return res.json({
                message: "You left the channel"
            });

        } catch (error) {

            console.error("Leave channel error:", error);

            return res.status(500).json({
                error: "Could not leave channel"
            });

        }

    }
);

/* =====================================================
   RENAME CHANNEL
===================================================== */

app.put(
    "/api/channels/:channelId",
    authenticate,
    authenticateChannelOwner,
    async (req, res) => {

        try {

            const name =
                String(req.body.name || "").trim();

            if (!name) {

                return res.status(400).json({
                    error: "Channel name required"
                });

            }

            if (name.length > 50) {

                return res.status(400).json({
                    error: "Channel name cannot exceed 50 characters"
                });

            }

            req.channel.name = name;

            await req.channel.save();

            io.emit("channelUpdated", {
                channelId: req.channel._id.toString()
            });

            return res.json({

                message: "Channel renamed",

                channel: req.channel

            });

        } catch (error) {

            console.error("Rename channel error:", error);

            return res.status(500).json({
                error: "Could not rename channel"
            });

        }

    }
);

/* =====================================================
   CHANGE CHANNEL PRIVACY
===================================================== */

app.put(
    "/api/channels/:channelId/privacy",
    authenticate,
    authenticateChannelOwner,
    async (req, res) => {

        try {

            if (
                typeof req.body.isPrivate !==
                "boolean"
            ) {

                return res.status(400).json({
                    error: "isPrivate must be true or false"
                });

            }

            req.channel.isPrivate =
                req.body.isPrivate;

            await req.channel.save();

            io.emit("channelUpdated", {
                channelId: req.channel._id.toString()
            });

            return res.json({

                message: "Channel privacy updated",

                isPrivate:
                    req.channel.isPrivate

            });

        } catch (error) {

            console.error(
                "Privacy update error:",
                error
            );

            return res.status(500).json({
                error: "Could not update privacy"
            });

        }

    }
);

/* =====================================================
   DELETE CHANNEL
===================================================== */

app.delete(
    "/api/channels/:channelId",
    authenticate,
    authenticateChannelOwner,
    async (req, res) => {

        try {

            const channelId =
                req.channel._id;

            /*
             * Delete channel messages first.
             */

            await Message.deleteMany({
                channel: channelId
            });

            await Channel.deleteOne({
                _id: channelId
            });

            io.emit("channelDeleted", {
                channelId:
                    channelId.toString()
            });

            return res.json({
                message: "Channel deleted"
            });

        } catch (error) {

            console.error(
                "Delete channel error:",
                error
            );

            return res.status(500).json({
                error: "Could not delete channel"
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
    authenticateChannelMember,
    async (req, res) => {

        try {

            const messages =
                await Message.find({
                    channel: req.channel._id
                })
                .populate(
                    "sender",
                    "username avatar"
                )
                .sort({
                    createdAt: 1
                })
                .limit(100);

            return res.json(messages);

        } catch (error) {

            console.error(
                "Message loading error:",
                error
            );

            return res.status(500).json({
                error: "Could not load messages"
            });

        }

    }
);

/* =====================================================
   SOCKET AUTHENTICATION
===================================================== */

io.use(async (socket, next) => {

    try {

        const token =
            socket.handshake.auth?.token;

        if (!token) {

            return next(
                new Error(
                    "Authentication required"
                )
            );

        }

        const user =
            await User.findOne({
                authToken: token
            });

        if (!user) {

            return next(
                new Error(
                    "Invalid authentication"
                )
            );

        }

        socket.user = user;

        next();

    } catch (error) {

        console.error(
            "Socket authentication error:",
            error
        );

        next(
            new Error(
                "Authentication failed"
            )
        );

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
        async (channelId, callback) => {

            try {

                if (!validObjectId(channelId)) {

                    if (callback) {
                        callback({
                            success: false,
                            error: "Invalid channel ID"
                        });
                    }

                    return;
                }

                const channel =
                    await Channel.findOne({

                        _id: channelId,

                        members: user._id

                    });

                if (!channel) {

                    if (callback) {
                        callback({
                            success: false,
                            error:
                                "You are not a member of this channel"
                        });
                    }

                    return;
                }

                /*
                 * Leave previous CELDEX channel rooms.
                 */

                for (const room of socket.rooms) {

                    if (
                        room.startsWith("channel:")
                    ) {

                        socket.leave(room);

                    }

                }

                socket.join(
                    `channel:${channelId}`
                );

                socket.currentChannel =
                    channelId;

                if (callback) {

                    callback({
                        success: true
                    });

                }

            } catch (error) {

                console.error(
                    "Join channel error:",
                    error
                );

                if (callback) {

                    callback({
                        success: false,
                        error: "Could not join channel"
                    });

                }

            }

        }
    );

    /* =================================================
       SEND MESSAGE
    ================================================= */

    socket.on(
        "sendMessage",
        async (data, callback) => {

            try {

                const {
                    channelId,
                    text
                } = data || {};

                if (
                    !channelId ||
                    typeof text !== "string"
                ) {

                    if (callback) {
                        callback({
                            success: false,
                            error: "Invalid message"
                        });
                    }

                    return;
                }

                const cleanText =
                    text.trim();

                if (!cleanText) {

                    if (callback) {
                        callback({
                            success: false,
                            error: "Message cannot be empty"
                        });
                    }

                    return;
                }

                if (cleanText.length > 2000) {

                    if (callback) {
                        callback({
                            success: false,
                            error:
                                "Message cannot exceed 2000 characters"
                        });
                    }

                    return;
                }

                /*
                 * CRITICAL SECURITY CHECK:
                 *
                 * A user can only send a message
                 * if they are currently a member.
                 */

                const channel =
                    await Channel.findOne({

                        _id: channelId,

                        members: user._id

                    });

                if (!channel) {

                    if (callback) {

                        callback({
                            success: false,
                            error:
                                "You are not a member of this channel"
                        });

                    }

                    return;
                }

                const message =
                    await Message.create({

                        sender: user._id,

                        channel: channel._id,

                        text: cleanText

                    });

                const fullMessage =
                    await Message.findById(
                        message._id
                    )
                    .populate(
                        "sender",
                        "username avatar"
                    );

                io.to(
                    `channel:${channelId}`
                )
                .emit(
                    "newMessage",
                    fullMessage
                );

                if (callback) {

                    callback({
                        success: true,
                        message: fullMessage
                    });

                }

            } catch (error) {

                console.error(
                    "Message error:",
                    error
                );

                if (callback) {

                    callback({
                        success: false,
                        error: "Could not send message"
                    });

                }

            }

        }
    );

    /* =================================================
       VOICE JOIN
    ================================================= */

    socket.on(
        "voiceJoin",
        async (roomId, callback) => {

            try {

                if (!roomId) {

                    if (callback) {
                        callback({
                            success: false,
                            error: "Voice room required"
                        });
                    }

                    return;
                }

                /*
                 * Only allow voice rooms for channels
                 * the user actually belongs to.
                 */

                if (validObjectId(roomId)) {

                    const channel =
                        await Channel.findOne({

                            _id: roomId,

                            members: user._id

                        });

                    if (!channel) {

                        if (callback) {
                            callback({
                                success: false,
                                error:
                                    "You are not a member of this channel"
                            });
                        }

                        return;
                    }

                }

                socket.join(
                    `voice:${roomId}`
                );

                socket.currentVoiceRoom =
                    roomId;

                socket.to(
                    `voice:${roomId}`
                )
                .emit(
                    "voiceUserJoined",
                    {
                        userId:
                            user._id.toString(),

                        username:
                            user.username,

                        avatar:
                            user.avatar
                    }
                );

                if (callback) {

                    callback({
                        success: true
                    });

                }

            } catch (error) {

                console.error(
                    "Voice join error:",
                    error
                );

                if (callback) {

                    callback({
                        success: false,
                        error: "Could not join voice"
                    });

                }

            }

        }
    );

    /* =================================================
       VOICE SIGNAL
    ================================================= */

    socket.on(
        "voiceSignal",
        (data) => {

            if (!data?.roomId) {
                return;
            }

            socket.to(
                `voice:${data.roomId}`
            )
            .emit(
                "voiceSignal",
                {
                    from: socket.id,

                    userId:
                        user._id.toString(),

                    signal:
                        data.signal
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

            if (!roomId) {
                return;
            }

            socket.leave(
                `voice:${roomId}`
            );

            socket.to(
                `voice:${roomId}`
            )
            .emit(
                "voiceUserLeft",
                {
                    userId:
                        user._id.toString()
                }
            );

            if (
                socket.currentVoiceRoom ===
                roomId
            ) {

                socket.currentVoiceRoom = null;

            }

        }
    );

    /* =================================================
       DISCONNECT
    ================================================= */

    socket.on(
        "disconnect",
        async () => {

            try {

                console.log(
                    `🔴 ${user.username} disconnected`
                );

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

server.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `🚀 CELDEX server running on port ${PORT}`
        );

    }
);
