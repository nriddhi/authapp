const authD = require('../models/AuthD');
const Token = require('../models/mailToken');
const sendEmail = require('../utils/sendEmail');
const passport = require("passport");
const jwt = require("jsonwebtoken");
const {getAdminUser, updateProfile, addCat} = require('./adminData');
const {verifyToken, getUser, refreshToken,login, logout} = require("./AuthController");
const router = require('express').Router();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require("multer");
const path = require("path");
const cloud = require('../utils/cloud');

  
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


  router.post('/register', async(req, res) => {

    try {
      if(req.body && req.body.name && req.body.username && req.body.password)
      {
      const username = await authD.findOne({ username: req.body.username });
      if(username) return res.status(406).json({code:'u406',err: "Username Taken"});

      const email = await authD.findOne({ email: req.body.email });
      if(email) return res.status(406).json({code:'e406',err: "Email Already Exists"});

      const salt = await bcrypt.genSalt(15);
      const hashedPass = await bcrypt.hash(req.body.password, salt);
      
         const newUser = new authD({
          name: req.body.name,
          username : req.body.username,
          email : req.body.email,
          password : hashedPass
     });

      const user = await newUser.save();

      const etoken = await new Token({
            userId: user._id,
            token : crypto.randomBytes(24).toString('hex')
      }).save();
      console.log(etoken);
      const msg= 'SignUp Verfication<nayeemriddhi.info>';
      const url = `${process.env.Client_URL}/users/${etoken.userId}/verify/${etoken.token}`;
      const htmlmsg =`<p>Please click the link for Verify your Email ${url} Thank you and regards</p>`;
      await sendEmail(user.email, msg, htmlmsg );

      res.status(200).json({msg:'success'});

    } else {
      return res.status(400).json({code: 'rqf400', msg: 'Required fields are missing'},);
    }
        }
    catch (err)
        { res.status(500).json(err); }    

  });

  router.post('/token', async(req, res) => {

  try {
    const userId = await Token.findOne({userId: req.body.param.id});
    if(!userId) return res.status(404).json({code:'ui404', msg:'User ID not found'});

    const token = await Token.findOne({token: req.body.param.token});
    if(!token) return res.status(404).json({code:'t404', msg:'Token not found'});

    const values = await authD.findOne({_id: req.body.param.id});

    if(userId && token && values?.verified===false)
  {
  await Token.deleteMany({userId:token.userId});
  await authD.findByIdAndUpdate(values._id, {verified:true});
  return res.status(200).json({code:'v200', msg:'User Verified'});
  
   }
  else { 
  res.status(404).json({code:'av201', msg:'Already Verified'});
  }

  }
  catch (err)
  { res.status(500).json(err)}

  });

  router.post('/resetPass', async(req, res) => {
   try {
    const salt = await bcrypt.genSalt(15);
    const updatepass = await bcrypt.hash(req.body.matchPwd, salt);
    const verfiedChk = await authD.findOne({_id:req.body.rId});
    const rtoken = await Token.findOne({token:req.body.rToken});

    if(rtoken && verfiedChk?.verified===true)
    {
      await authD.findByIdAndUpdate(req.body.rId, {password:updatepass});
      await Token.findByIdAndRemove(rtoken._id);
      res.status(200).json({code:'rtSuccess',message:'Password updated successfully'});
    }
    else if(rtoken && verfiedChk?.verified===false){
      res.status(200).json({code:'notVerified',message:'User not verified'});
    }
    else {
      res.status(200).json({code:'rtExpired',message:'Token Expired or Password Updated Already'});
    }
    
   }
   catch(err){
    res.status(500).json({code:'rntvalid',message:'Request Not Valid'});
   }

  });

  router.post('/sendfEmail', async (req, res) => {
   try {
  
    const chkEmail = await authD.findOne({email: req.body.fEmail});
  
    if(chkEmail && chkEmail?.verified==true)
    {
       const ftoken = await new Token({
        userId: chkEmail._id,
        token : crypto.randomBytes(24).toString('hex')
       }).save();
       const msg= 'Reset Password<nayeemriddhi.info>';
       const url = `${process.env.Client_URL}/users/${ftoken.userId}/reset/${ftoken.token}`;
       const htmlmsg =`<p>Please click the link for Reset your password ${url} Thank you and regards</p>`;
       await sendEmail(chkEmail.email, msg, htmlmsg);
       res.status(200).json({code:'rp200', msg:'Reset Password Email Sent successfully'});
    }
    else if(chkEmail && chkEmail?.verified==false)
    {
     const etoken = await new Token({
      userId: chkEmail._id,
      token : crypto.randomBytes(24).toString('hex')
     }).save();
     const msg= 'SignUp Verification<nayeemriddhi.info>';
     const url = `${process.env.Client_URL}/users/${etoken.userId}/verify/${etoken.token}`;
     const htmlmsg =`<p>Please click the link for Verify your Email ${url} Thank you and regards</p>`;
     await sendEmail(chkEmail.email, msg, htmlmsg );
     res.status(200).json({code:'sv200', msg:'SignUp Verification Email Sent successfully'});
    } 
  else {  

    res.status(404).json({code:'nf404', msg:'Email Not Registered'});

   }

}
catch (err) { res.status(500).json(err) }
 });


router.get("/getuser", verifyToken, getAdminUser);
router.post("/updateProfile", upload.single('profile'), updateProfile);
router.post("/addCategories", addCat);
router.get("/refresh", refreshToken, getUser);
router.post("/login", login );
router.post("/logout", logout);

  router.get('/google',
  passport.authenticate('google', { scope: ['email', 'profile'] }));

  router.get('/google/callback', passport.authenticate('google', {
    failureRedirect: "/",
  }), function(req,res){

    const accessToken = jwt.sign({
      uId : req.user._id
   }, process.env.JWT_SECRET, {
     expiresIn: "3500s",
   });

   if (req.cookies['ecom_token']) {
     req.cookies['ecom_token'] = "";
   }
   
   res.cookie('ecom_token', accessToken, {
     path: "/",
     httpOnly: true,
     sameSite: "lax",
   });
    
    res.redirect(process.env.BASE_URL);
   
  });

  router.get('/facebook',
  passport.authenticate('facebook'));

  router.get('/facebook/callback', passport.authenticate('facebook', {
    failureRedirect: "/",
  }), function(req,res){
    
    const accessToken = jwt.sign({
      uId : req.user._id
   }, process.env.JWT_SECRET, {
     expiresIn: "3500s",
   });

   if (req.cookies['ecom_token']) {
     req.cookies['ecom_token'] = "";
   }
   
   res.cookie('ecom_token', accessToken, {
     path: "/",
     httpOnly: true,
     sameSite: "lax",
   });
    
    res.redirect(process.env.BASE_URL);
   
  });

  router.get('/twitter',
  passport.authenticate('twitter'));

  router.get('/twitter/callback', passport.authenticate('twitter', {
    failureRedirect: "/",
  }), function(req,res){
    
    const accessToken = jwt.sign({
      uId : req.user._id
   }, process.env.JWT_SECRET, {
     expiresIn: "3500s",
   });

   if (req.cookies['ecom_token']) {
     req.cookies['ecom_token'] = "";
   }
   
   res.cookie('ecom_token', accessToken, {
     path: "/",
     httpOnly: true,
     sameSite: "lax",
   });
    
    res.redirect(process.env.BASE_URL);
   
  });



module.exports = router;