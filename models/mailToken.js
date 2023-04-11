const mongoose = require('mongoose');
const schema = mongoose.Schema;

const tokenSchema = new mongoose.Schema({

    userId : {
       type: schema.Types.ObjectId,
       reuired:true,
       ref: "authD"
    },

    token: {
        type:String,
        required:true
    },

    createdAT : { type:Date, default:Date.now(), expires:3600 }

});

module.exports = mongoose.model('token', tokenSchema);