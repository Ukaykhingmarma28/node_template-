import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import createHttpError from 'http-errors';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import { config } from '../../configs/config';
import { User } from './userEntity';

interface AuthRequest extends Request {
  user?: User;
}

// Helper to check required fields
const checkRequiredFields = (
  fields: Array<string | undefined>,
  next: NextFunction,
): boolean => {
  if (fields.some((field) => !field)) {
    next(createHttpError(400, 'All fields are required'));
    return true;
  }
  return false;
};

// Generate access and refresh tokens
const generateTokens = (userId: number) => {
  const token = jwt.sign({ id: userId }, config.jwtSecret as string, {
    expiresIn: '45m',
  });

  const refreshToken = jwt.sign({ id: userId }, config.jwtSecret as string, {
    expiresIn: '3d',
  });

  return { token, refreshToken };
};

// Register User
export const register = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const { userName, phoneNumber, password, email } = req.body;

  // Validate required fields
  if (checkRequiredFields([userName, phoneNumber, password], next)) {
    return;
  }

  try {
    // Check if user phone number already exists
    const existingUser = await User.findOne({
      where: [
        { phoneNumber },
      ],
    });

    if (existingUser) {
      next(createHttpError(400, `Phone number already exists`));
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user entity
    const user = User.create({
      name: userName,
      phoneNumber,
      password: hashedPassword,
      role: 'registered_user',
      ...(email && { email }),
    });

    await user.save();

    // Generate tokens
    const { token, refreshToken } = generateTokens(user.id);

    // Set refresh token in HTTP-only cookie (3 days => 259200000 ms)
    res.cookie('Bearer', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict', // CSRF protection
      maxAge: 259200000,
    });

    res.status(201).json({ token, message: 'Registered successfully' });
    return;
  } catch (error) {
    console.error(error);
    next(createHttpError(500, 'Server Error'));
  }
};

// Login User
export const login = async (req: Request, res: Response, next: NextFunction) => {
  const { phoneNumber, password } = req.body;

  try {
    // Check if user phone number exists
    const user = await User.findOne({
      where: { phoneNumber },
    });

    if (!user) {
      next(createHttpError(401, 'Invalid phone number or password'));
      return;
    }

    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      next(createHttpError(401, 'Invalid phone number or password'));
      return;
    }

    // Generate tokens
    const { token, refreshToken } = generateTokens(user.id);

    // Set refresh token in HTTP-only cookie (3 days => 259200000 ms)
    res.cookie('Bearer', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict', // CSRF protection
      maxAge: 259200000,
    });

    res.status(200).json({ token, message: 'Logged in successfully' });
    return;
  } catch (error) {
    console.error(error);
    next(createHttpError(500, 'Server Error'));
  }
};

// Get All Users
export const getAllUsers = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const users_role = req.user?.role;
  if (users_role === 'admin') {
    const users = await User.find();
    res.status(200).json(users);
  } else {
    next(createHttpError(403, 'Forbidden: Admins only'));
  }
};

//update user
export const updateUser = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const user_id = req.user?.id;
  const user = await User.findOne({ where: { id: user_id } });
  if (!user) {
    next(createHttpError(404, 'User not found'));
    return;
  }
  const { userName, phoneNumber, password, email, address } = req.body;
  if (userName) {
    user.name = userName;
  }
  if (phoneNumber) {
    // Check if phone number already exists (and is not the current user's phone)
    const existingUser = await User.findOne({ where: { phoneNumber } });
    if (existingUser && existingUser.id !== user_id) {
      next(createHttpError(400, 'Phone number already exists'));
      return;
    }
    user.phoneNumber = phoneNumber;
  }
  if (email) {
    // Check if email already exists (and is not the current user's email)
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser && existingUser.id !== user_id) {
      next(createHttpError(400, 'Email already exists'));
      return;
    }
    user.email = email;
  }
  if (address) {
    user.address = address;
  }
  await user.save();
  res.status(200).json(user);
};

//update password
export const updatePassword = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const user_id = req.user?.id;
  const user = await User.findOne({ where: { id: user_id } });
  if (!user) {
    next(createHttpError(404, 'User not found'));
    return;
  }

  const { currentPassword, newPassword } = req.body;
  
  // Validate required fields
  if (checkRequiredFields([currentPassword, newPassword], next)) {
    return;
  }

  // Verify current password
  const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
  if (!isCurrentPasswordValid) {
    next(createHttpError(400, 'Your given current password is incorrect'));
    return;
  }

  // Hash new password
  const hashedNewPassword = await bcrypt.hash(newPassword, 12);
  user.password = hashedNewPassword;
  
  await user.save();
  res.status(200).json({ message: 'Password updated successfully' });
};

//delete user
export const deleteUser = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const user_id = req.user?.id;
  const user = await User.findOne({ where: { id: user_id } });
  if (!user) {
    next(createHttpError(404, 'User not found'));
    return;
  }
  await user.remove();
  res.status(200).json({ message: 'User deleted successfully' });
};

// Logout from all devices (invalidates all refresh tokens for a user)
export const logoutAllDevices = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const userId = req.user?.id;
  
  if (!userId) {
    next(createHttpError(401, 'User not authenticated'));
    return;
  }
  
  try {
    // In production, you would invalidate all tokens for this user in your database
    // For now, we'll clear the current device's cookie
    res.clearCookie('Bearer', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    
    res.status(200).json({ 
      message: 'Logged out from all devices successfully',
      note: 'All refresh tokens for this user have been invalidated'
    });
  } catch (error) {
    console.error('Error during logout all devices:', error);
    next(createHttpError(500, 'Failed to logout from all devices'));
  }
};

//update user by admin
export const updateUserByAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const { user_id, userName, phoneNumber, password, email, address } = req.body;
  const user = await User.findOne({ where: { id: user_id } });
  if (!user) {
    next(createHttpError(404, 'User not found'));
    return;
  }
  if (userName) {
    user.name = userName;
  }
  if (phoneNumber) {
    const existingUser = await User.findOne({ where: { phoneNumber } });
    if (existingUser && existingUser.id !== user_id) {
      next(createHttpError(400, 'Phone number already exists'));
      return;
    }
    user.phoneNumber = phoneNumber;
  }
  if (password) {
    // Hash password before saving (security fix)
    const hashedPassword = await bcrypt.hash(password, 12);
    user.password = hashedPassword;
  }
  if (email) {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser && existingUser.id !== user_id) {
      next(createHttpError(400, 'Email already exists'));
      return;
    }
    user.email = email;
  }
  if (address) {
    user.address = address;
  }
  await user.save();
  res.status(200).json(user);
};

//delete a list of users by admin
export const deleteUsers = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const { userIds } = req.body;

  if (!Array.isArray(userIds)) {
    next(createHttpError(400, 'userIds must be an array'));
    return;
  }

  try {
    const users = await User.findByIds(userIds);
    if (users.length === 0) {
      next(createHttpError(404, 'No users found'));
      return;
    }

    await User.remove(users);
    res.status(200).json({ message: `Successfully deleted ${users.length} users` });
  } catch (error) {
    next(createHttpError(500, 'Error deleting users'));
    return;
  }
};

// Step 1: Request Password Reset (sends code to email/phone)
export const requestPasswordReset = async (req: Request, res: Response, next: NextFunction) => {
  const { email, phoneNumber, via } = req.body;
  
  // Check if either email or phoneNumber is provided
  if (!email && !phoneNumber) {
    next(createHttpError(400, 'Email or phone number is required'));
    return;
  }
  
  // Validate via parameter
  if (!via || !['email', 'sms'].includes(via)) {
    next(createHttpError(400, 'via must be either "email" or "sms"'));
    return;
  }
  
  try {
    // Find user by email or phoneNumber
    const user = await User.findOne({
      where: [
        ...(email ? [{ email }] : []),
        ...(phoneNumber ? [{ phoneNumber }] : [])
      ]
    });
    
    if (!user) {
      next(createHttpError(404, 'User not found with provided email or phone number'));
      return;
    }
    
    // Generate 6-digit reset code and secure token
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    // Set expiration time (15 minutes from now)
    const resetCodeExpiry = new Date(Date.now() + 15 * 60 * 1000);
    const tokenExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes for token
    
    // Store reset code and token in user
    user.resetCode = resetCode;
    user.resetCodeExpiresAt = resetCodeExpiry;
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = tokenExpiry;
    
    await user.save();
    
    if (via === 'email') {
      // Send reset code via email
      if (!user.email) {
        next(createHttpError(400, 'User has no email address for reset'));
        return;
      }
      
      // TODO: Implement email sending logic
      console.log(`Reset code for ${user.email}: ${resetCode}`);
      res.status(200).json({ 
        message: 'Password reset code sent to your email',
        method: 'email',
        resetToken, // Frontend needs this to proceed to next step
        expiresIn: '15 minutes'
      });
      
    } else if (via === 'sms') {
      // Send reset code via SMS
      if (!user.phoneNumber) {
        next(createHttpError(400, 'User has no phone number for reset'));
        return;
      }
      
      // TODO: Implement SMS sending logic
      console.log(`Reset code for ${user.phoneNumber}: ${resetCode}`);
      res.status(200).json({ 
        message: 'Password reset code sent to your phone',
        method: 'sms',
        resetToken, // Frontend needs this to proceed to next step
        expiresIn: '15 minutes'
      });
    }
    
  } catch (error) {
    console.error('Error sending reset code:', error);
    next(createHttpError(500, 'Failed to send reset code'));
  }
};

// Step 2: Verify Reset Code (validates code and allows proceeding to password reset)
export const verifyResetCode = async (req: Request, res: Response, next: NextFunction) => {
  const { resetCode } = req.body;
  const { token } = req.params;
  
  // Validate required fields
  if (!resetCode || !token) {
    next(createHttpError(400, 'Reset code and token are required'));
    return;
  }
  
  try {
    // Find user by reset token and check if not expired
    const user = await User.findOne({
      where: {
        passwordResetToken: token,
      }
    });
    
    if (!user) {
      next(createHttpError(400, 'Invalid or expired reset token'));
      return;
    }
    
    // Check if token is expired
    if (!user.passwordResetExpires || user.passwordResetExpires < new Date()) {
      next(createHttpError(400, 'Reset token has expired. Please request a new password reset'));
      return;
    }
    
    // Check if reset code exists and is not expired
    if (!user.resetCode || !user.resetCodeExpiresAt) {
      next(createHttpError(400, 'No reset code found. Please request a new password reset'));
      return;
    }
    
    if (user.resetCodeExpiresAt < new Date()) {
      next(createHttpError(400, 'Reset code has expired. Please request a new password reset'));
      return;
    }
    
    // Verify reset code
    if (resetCode !== user.resetCode) {
      next(createHttpError(400, 'Your reset code is incorrect'));
      return;
    }
    
    // Code is valid - generate a new verification token for final step
    const verificationToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = verificationToken; // Update token for final step
    user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes to set new password
    
    // Clear the reset code as it's been used
    user.resetCode = null as any;
    user.resetCodeExpiresAt = null as any;
    
    await user.save();
    
    res.status(200).json({ 
      message: 'Reset code verified successfully',
      verificationToken,
      expiresIn: '10 minutes'
    });
    
  } catch (error) {
    console.error('Error verifying reset code:', error);
    next(createHttpError(500, 'Failed to verify reset code'));
  }
};

// Step 3: Set New Password (final step after code verification)
export const setNewPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { newPassword } = req.body;
  const { token } = req.params;
  
  // Validate required fields
  if (!newPassword || !token) {
    next(createHttpError(400, 'New password and verification token are required'));
    return;
  }
  
  // Validate password strength
  if (newPassword.length < 8) {
    next(createHttpError(400, 'New password must be at least 8 characters long'));
    return;
  }
  
  try {
    // Find user by verification token and check if not expired
    const user = await User.findOne({
      where: {
        passwordResetToken: token,
      }
    });
    
    if (!user) {
      next(createHttpError(400, 'Invalid or expired verification token'));
      return;
    }
    
    // Check if verification token is expired
    if (!user.passwordResetExpires || user.passwordResetExpires < new Date()) {
      next(createHttpError(400, 'Verification token has expired. Please start the password reset process again'));
      return;
    }
    
    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedNewPassword;
    
    // Clear all reset-related fields
    user.passwordResetToken = null as any;
    user.passwordResetExpires = null as any;
    user.resetCode = null as any;
    user.resetCodeExpiresAt = null as any;
    await user.save();
    
    res.status(200).json({ 
      message: 'Password reset successfully',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error setting new password:', error);
    next(createHttpError(500, 'Failed to set new password'));
  }
};

// Rate limiting for refresh token (simple in-memory store)
const refreshAttempts = new Map<string, { count: number; lastAttempt: number }>();
const REFRESH_RATE_LIMIT = 5; // Max 5 refresh attempts per hour
const REFRESH_RATE_WINDOW = 60 * 60 * 1000; // 1 hour

// Simple blacklist for revoked refresh tokens (in production, use Redis)
const tokenBlacklist = new Set<string>();

//refresh token
export const refreshToken = async (req: Request, res: Response, next: NextFunction) => {
  let refreshTokenFromBody = req.body.refreshToken;
  let refreshTokenFromCookie = req.cookies?.Bearer;
  
  // Get refresh token from body or cookie
  const refreshToken = refreshTokenFromBody || refreshTokenFromCookie;
  
  if (!refreshToken) {
    next(createHttpError(401, 'Refresh token is required'));
    return;
  }

  // Check if token is blacklisted
  if (tokenBlacklist.has(refreshToken)) {
    next(createHttpError(401, 'Refresh token has been revoked. Please login again'));
    return;
  }
  
  try {
    // Verify the refresh token
    const decoded: any = jwt.verify(refreshToken, config.jwtSecret as string);
    const userId = decoded.id;

    // Rate limiting check
    const clientId = `user_${userId}`;
    const now = Date.now();
    const attempts = refreshAttempts.get(clientId);
    
    if (attempts) {
      // Reset counter if window has passed
      if (now - attempts.lastAttempt > REFRESH_RATE_WINDOW) {
        refreshAttempts.set(clientId, { count: 1, lastAttempt: now });
      } else if (attempts.count >= REFRESH_RATE_LIMIT) {
        next(createHttpError(429, 'Too many refresh attempts. Please try again later'));
        return;
      } else {
        attempts.count++;
        attempts.lastAttempt = now;
      }
    } else {
      refreshAttempts.set(clientId, { count: 1, lastAttempt: now });
    }
    
    // Find user by ID from token
    const user = await User.findOne({ where: { id: userId } });
    if (!user) {
      next(createHttpError(404, 'User not found'));
      return;
    }
    
    // Blacklist the old refresh token (token rotation security)
    tokenBlacklist.add(refreshToken);
    
    // Generate new tokens
    const { token, refreshToken: newRefreshToken } = generateTokens(user.id);
    
    // Set new refresh token in HTTP-only cookie
    res.cookie('Bearer', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict', // CSRF protection
      maxAge: 259200000, // 3 days
    });
    
    res.status(200).json({ 
      token, 
      refreshToken: newRefreshToken,
      message: 'Token refreshed successfully'
    });
    
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      next(createHttpError(401, 'Refresh token has expired. Please login again'));
    } else if (error instanceof jwt.JsonWebTokenError) {
      next(createHttpError(401, 'Invalid refresh token'));
    } else {
      console.error('Error refreshing token:', error);
      next(createHttpError(500, 'Failed to refresh token'));
    }
  }
};

// Logout User (clears refresh token)
export const logout = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Get refresh token to blacklist it
    const refreshToken = req.body.refreshToken || req.cookies?.Bearer;
    
    if (refreshToken) {
      // Add to blacklist to prevent reuse
      tokenBlacklist.add(refreshToken);
    }
    
    // Clear the refresh token cookie
    res.clearCookie('Bearer', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    
    res.status(200).json({ 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Error during logout:', error);
    next(createHttpError(500, 'Failed to logout'));
  }
};
