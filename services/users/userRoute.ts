import { Router } from 'express';
import { 
  login, 
  register, 
  getAllUsers, 
  updateUser, 
  updateUserByAdmin, 
  deleteUsers, 
  deleteUser, 
  updatePassword, 
  requestPasswordReset, 
  setNewPassword, 
  verifyResetCode,
  refreshToken,
  logout,
  logoutAllDevices
} from './userController';
import authMiddleware from '../../middleware/auth';
import isAdmin from '../../middleware/isAdmin';

const router = Router();

// Authentication routes
router.post('/register', register);
router.post('/login', login);
router.post('/refresh', refreshToken);
router.post('/logout', logout);
router.post('/logout-all', authMiddleware, logoutAllDevices);

// User management routes
router.get('/all', authMiddleware, isAdmin, getAllUsers);
router.put('/update', authMiddleware, updateUser);
router.put('/update-password', authMiddleware, updatePassword);
router.delete('/delete', authMiddleware, deleteUser);

// Admin routes
router.delete('/delete-users', authMiddleware, isAdmin, deleteUsers);
router.put('/update-user-by-admin', authMiddleware, isAdmin, updateUserByAdmin);

// Password reset routes
router.post('/request-password-reset', requestPasswordReset);
router.post('/verify-reset-code/:token', verifyResetCode);
router.post('/set-new-password/:token', setNewPassword);

export default router;
