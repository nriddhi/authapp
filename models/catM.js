const mongoose = require("mongoose");

const CatSchema = new mongoose.Schema(
  {
    catName: {
        type: String,
        default: "",
      },

    catSlug : {
        type:String,
        default: "",
    },

    parentCat: {
      type: String,
      default: "",
    },

    description: {
      type: String,
      default: '',
    },

  },
  { timestamps: true }
);

const CatsModel = mongoose.model("categories", CatSchema);
module.exports = CatsModel;
