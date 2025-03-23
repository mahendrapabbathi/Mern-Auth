import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import sendEmail from "../nodemailer.js";
import { EMAIL_VERIFY_TEMPLATE,PASSWORD_RESET_TEMPLATE } from "../config/emailTemplates.js";



export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required!" });
    }

    try {
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User already exists!" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        await sendEmail({
            email: email,
            to:email,
            subject: "Welcome to MahiBlog!",
            message: `Your Registered successfully with ${email}`
        });

        return res.status(201).json({ success: true, message: "Registered successfully! A confirmation email has been sent." });

    } catch (error) {
        console.error("Registration error:", error.message);
        return res.status(500).json({ success: false, message: "Registration failed. Please try again." });
    }
};


export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "Email and password are required" });
    }

    try {

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "Invalid Email" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({ success: false, message: "Invalid Password" });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        return res.json({ success: true, message: "Logged In Successfully!" });

    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        return res.json({ success: true, message: "Logged Out Successfully!" })
    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

export const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;

        const user = await userModel.findById(userId);

        if (user.isAccountVerified) {
            return res.status(400).json({ success: false, message: "Account already verified." });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        // Save OTP and its expiration time to the user
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; // Expires in 24 hours

        await user.save();
        
        const emailContent = EMAIL_VERIFY_TEMPLATE
  .replace(/{{otp}}/g, otp)
  .replace(/{{email}}/g, user.email);


        await sendEmail({
            email: user.email,
            subject: "Account Verification OTP",
            // message: `Your OTP is ${otp}. Please use this code to verify your account.`,
            
            html:emailContent
        });

        res.status(200).json({ success: true, message: "Verification OTP sent to your email." });

    } catch (error) {
        console.error("Error sending OTP:", error.message);
        res.status(500).json({ success: false, message: "Failed to send OTP. Please try again." });
    }
};

export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({ success: false, message: "Missing Details!" })
    }

    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ sucess: false, message: "User not found" })
        }

        if (user.verifyOtp === "" || user.verifyOtp !== otp) {
            return res.json({ sucess: false, message: "Invalid OTP" });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ sucess: false, message: "OTP Expired" });
        }

        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpireAt = 0;

        await user.save();
        return res.json({ success: true, message: "Email Verify Successfully" })

    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

//check if the user is authenticated
export const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true })
    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

// send password reset OTP
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ success: false, message: "Email is Required" })
    }

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User Not Found" })
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

    // Save OTP and its expiration time to the user
    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

    await user.save();

    await sendEmail({
        email: user.email,
        subject: "Password Reset OTP",
        // message: `Your OTP for resetting your pasword is ${otp}. Use this OTP to proceed with resetting your password.`, 
        html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
    });

    return res.json({success:true,message:"OTP sent to your email"});

    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

// Reset Your Password

export const resetPassword = async (req,res)=>{
    const {email,otp,newPassword} = req.body;
    
    if(!email || !otp || !newPassword){
        return res.json({ success: false, message: "Email, OTP and New Password are required" })
    }

    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({ success: false, message: 'User Not Found' })
        }

        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({ success: false, message: "Invalid OTP" })
        }

        if(user.resetOtpExpireAt < Date.now()){
            return res.json({ success: false, message: "OTP Expired" })
        }

        const hashedPassword = await bcrypt.hash(newPassword,10);

        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;

        await user.save();
        return res.json({ success: true, message:"Password has been reset Successfully!"})
    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}