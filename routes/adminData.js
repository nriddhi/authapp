const authD = require('../models/AuthD');
const catM  = require('../models/catM');
const router = require('express').Router();
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const cloud = require('../utils/cloud');
const multer = require('multer');
const { response } = require('express');

const upload = multer({
  storage: multer.diskStorage({}),
  fileFilter: (req, file, cb) => {
    let ext = path.extname(file.originalname);  
    if (ext !== ".jpg" && ext !== ".jpeg" && ext !== ".png") {
      cb(new Error("File type is not supported"), false);
      return;
    }
    cb(null, true);
  },
   });

const getAdminUser = async (req, res, next) => {
    const cookieToken = req.cookies.ecom_token;
  
    if (!cookieToken) {
        return res.status(404).json({ code:'lo400', message: "No token found" });
      }
    jwt.verify(String(cookieToken), process.env.JWT_SECRET, async (error, user) => {
        if (error) {
          return res.status(400).json({code:'lou400', message: "Invalid Token" });
        }
        const userId = user.uId;
        const userDetails = await authD.findById(userId);  
     if(userDetails)
    {
        res.status(200).json({user:userDetails});
    }

      });
    
    
};

const updateProfile = async (req, res)  => {

  const salt = await bcrypt.genSalt(15);
  const hashedPass = await bcrypt.hash(req.body.password, salt);
  try {
    if(req.file?.path)
     result = await cloud.uploader.upload(req.file?.path);

     const profile = authD.findByIdAndUpdate(req.body.userid, {
      name: req.body.name,
      username : req.body.username,
      email : req.body.email,
      password: hashedPass,
      profilePic: result?.secure_url,
      address: req.body.address,
      mobile: req.body.mobile,
      gender: req.body.gender   

     }, function (err, docs) {
      if (err){
          console.log(err)
      }
      else{
          res.status(200).json({msg:'suceess'});
      }});
  }
  catch (err) { 
    res.status(500).json(err);
   }
   
}

const addCat = async(req, res) => {

try {
   const data = await new catM({
     catName : req.body.name,
     catSlug : req.body.slug,
     parentCat : req.body.parentCat,
     description: req.body.description
   }).save();
   res.status(200).json({success: "Data Saved successfully"});
}
catch (err) {
res.status(500).json({msg:err})
}

}

exports.getAdminUser = getAdminUser;
exports.updateProfile = updateProfile;
exports.addCat = addCat;