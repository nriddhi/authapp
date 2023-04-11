const mongoose = require("mongoose");
const crypto = require('crypto');


const UserSchema = new mongoose.Schema(
  {
    name: {
        type: String,
        required: true
      },

    username: {
      type: String,
      required:true,
      unique: true,
      index:true
    },

    email: {
      type: String,
      required:true,
      unique: true,
      index:true
    },

    social_id: {
      type: String,
      default: "",
    },

    password: {
      type: String,
      default: crypto.randomBytes(24).toString('hex'),
    },

    profilePic:{
      type: String,
      default: "",
    },

    role: {
      type:String,
      default:'customer'
    },

    address: {
      type: String,
      default:'',
    },

    mobile : {
    type: String,
    default:''
   },

    gender : {
    type: String,
    default:''
    },

    verified : {
      type: Boolean,
      default:false
    }

  },
  { timestamps: true }
);

const UsersModel = mongoose.model("users", UserSchema);
module.exports = UsersModel;

