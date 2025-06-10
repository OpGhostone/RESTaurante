const mongoose = require("mongoose")

const userSchema = new mongoose.Schema({
    username: {
        require: true,
        type: String
    },
    email: {
        require: true,
        type: String
    },
    password: {
        require: true,
        type: String
    }
})

const UserModel = mongoose.model("User", userSchema)
module.exports = UserModel
