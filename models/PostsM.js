const mongoose = require("mongoose");

const PostSchema = new mongoose.Schema(
  {
    title: {
        type: String,
        default: "",
      },

    description : {
        type:String,
        default: "",
    },

    categories: {
      type: String,
      default: "",
    },

    tags: {
      type: String,
      default: '',
    },
    
    featuredImg: {
      type: String,
      default: ''
    }

  },
  { timestamps: true }
);

const PostsModel = mongoose.model("posts", PostSchema);
module.exports = PostsModel;
