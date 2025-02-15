const express=require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { name } = require('ejs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();


const app = express();

//middleware
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(
  session({
      secret: 'your-secret-key', 
      resave: false,              // Prevents session from being saved back to the store unnecessarily
      saveUninitialized: false,   // Only save sessions when something is stored
      cookie: {
          secure: false,          // Set to `true` if using HTTPS
          httpOnly: true,         // Prevents client-side JavaScript from accessing the cookie
          maxAge: 1000 * 60 * 60  // Session expires in 1 hour (adjust as needed)
      }
  })
);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


//MongoDB connection
mongoose.connect(process.env.DB_URL,{
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(()=>{
    console.log('Connected to MongoDB');
}).catch((err)=>{
    console.error('Error connecting to MongoDB:',err);
});

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465, // Use 587 if 465 doesn't work
  secure: true, // true for port 465, false for 587
  auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PSWRD
  }
});

const userSchema = new mongoose.Schema({
    name: String,
    age: Number,
    gender: Boolean,
});

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  failedLoginAttempts: { type: Number, default: 0 },
  isLocked: { type: Boolean, default: false },
  email: { type: String, required: true, unique: true },
  resetPasswordToken: { type: String, default: null },
  resetPasswordExpires: { type: Date, default: null }
});

  
// Hash password before saving
adminSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare passwords
adminSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User',userSchema)
const Admin = mongoose.model('Admin', adminSchema);

//Requires admin
const requireLogin = (req, res, next) => {
  if (!req.session.admin) {
      return res.redirect('/login');
  }
  next();
};

   
//First render page for display all data
app.get('/',async(req,res)=> {
    try{
        const users = await User.find();
        res.render('index',{users, session: req.session});
    } catch(err){
        res.status(500).send('Error fetching users')
    }
});

//Search users by name
app.post('/',async(req,res)=> {
    try{
        const {searchName} = req.body;
        const users = searchName
        ? await User.find({ name: searchName.trim() })  // If Sname exists, search exactly by name
        : await User.find();
        res.render('index',{users, session: req.session});
    } catch(err){
        res.status(500).send('Error find users')
    }
});

// Create user
app.get('/add', requireLogin, async(req,res)=> {
    res.render('add');
});

// Return to main page after creating new user
app.post('/add', requireLogin, async(req,res)=> {
    try {
        const {name,age,gender}=req.body;
        const newUser = new User({name,gender,age})
        await newUser.save();
        res.redirect('/')
    } catch(err){
        res.status(500).send('Error creating user')
    }
});

//Redirect to edit page
app.get('/edit/:id', requireLogin, async (req, res) => {
    try{
        const user = await User.findById(req.params.id);
        res.render('edit', { user });
    } catch(err){
        res.status(500).send('Error render edit')
    }
    
});

// Update user parameters
app.post('/edit/:id', requireLogin, async(req,res)=>{
        try{
            const {id} = req.params;
            const {name,gender,age} = req.body;
            await User.findByIdAndUpdate(id, {name,gender,age});
            console.log(`User ${id} updated successfully`);
            res.redirect('/');
        } catch(err){
            res.status(500).send('Error editing user')
        }
});

// Delete user by resending it on deleting page and auto update general page (didnt finish)
app.get('/delete/:id', requireLogin, async(req,res)=>{
    try{
        const {id} = req.params;
        await User.findByIdAndDelete(id)
        console.log(`User ${id} delete successfully`);
        res.redirect('/');
    }catch(err){
        res.status(500).send('Error deleting user')
    }
});

//Register
app.get('/register', async(req,res)=>{
    res.render('register');
});

//Send registration form to database and has password
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  try {
      const existingAdmin = await Admin.findOne({ username });
      if (existingAdmin) {
          return res.status(400).send('Admin already exists');
      }

      const admin = new Admin({ username, password, email });
      await admin.save();
      res.redirect('/login');
  } catch (err) {
      res.status(500).send('Error registering admin');
  }
});


app.get('/login', async(req,res)=>{
    res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
      const admin = await Admin.findOne({ username });
      if (!admin) {
          return res.redirect('/login?error=Admin not found');
      }

      // Check if the account is locked
      if (admin.isLocked) {
          return res.redirect('/login?error=Account locked. Reset password.');
      }

      // Compare passwords
      const isPasswordValid = await admin.comparePassword(password);
      if (!isPasswordValid) {
          admin.failedLoginAttempts += 1;

          // Lock the account after 5 failed attempts
          if (admin.failedLoginAttempts >= 5) {
              admin.isLocked = true;
          }

          await admin.save();
          return res.redirect('/login?error=Invalid password');
      }

      // Reset failed attempts on successful login
      admin.failedLoginAttempts = 0;
      admin.isLocked = false;
      await admin.save();

      req.session.admin = admin;
      res.redirect('/');
  } catch (err) {
      res.redirect('/login?error=Error logging in');
  }
});


  // Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Could not log out');
    }
    res.redirect('/');
  });
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const admin = await Admin.findOne({ email });

  if (!admin) {
      return res.redirect('/forgot-password?error=Email not found');
  }

  // Generate reset token
  const resetToken = crypto.randomBytes(20).toString('hex');
  admin.resetPasswordToken = resetToken;
  admin.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiration
  await admin.save();

  // Send email with reset link
  const resetUrl = `https://goruplist.onrender.com/reset-password/${resetToken}`;
  const mailOptions = {
      to: admin.email,
      from: process.env.EMAIL,
      subject: 'Password Reset Request',
      text: `Click the following link to reset your password: ${resetUrl}`
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
        console.error("Nodemailer Error:", err);  // Log detailed error
        return res.redirect('/forgot-password?error=Error sending email');
    }
    console.log("Email sent:", info.response);  // Debugging success
    res.redirect('/login?message=Check your email for reset link');
  }); 
});

app.get('/reset-password/:token', async (req, res) => {
  const admin = await Admin.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() } // Ensure token is not expired
  });

  if (!admin) {
      return res.redirect('/forgot-password?error=Invalid or expired token');
  }

  res.render('reset-password', { token: req.params.token });
});

app.post('/reset-password/:token', async (req, res) => {
  const { password } = req.body;
  const admin = await Admin.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
  });

  if (!admin) {
      return res.redirect('/forgot-password?error=Invalid or expired token');
  }
  
  admin.failedLoginAttempts = 0;
  admin.isLocked=false;
  admin.password = password;  // Auto-hashed in `pre('save')`
  admin.resetPasswordToken = undefined;
  admin.resetPasswordExpires = undefined;

  await admin.save();

  res.redirect('/login?message=Password successfully reset');
});




//initialize port and short messege
const PORT = 3000;
app.listen(PORT, ()=>{
    console.log(`http://localhost:${PORT}`);
});
