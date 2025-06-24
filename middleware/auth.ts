import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import createHttpError from "http-errors";
import { User } from "../services/users/userEntity";
import { config } from "../configs/config";

export interface AuthRequest extends Request {
  user?: User;
}

const authMiddleware = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies && req.cookies.Bearer) {
    token = req.cookies.Bearer;
  }
  if (!token) {
    return next(createHttpError(401, "Not authorized, no token"));
  }

  try {
    const decoded: any = jwt.verify(token, config.jwtSecret as string);
    const userID = decoded.id;
    const user = await User.findOne({ where: { id: userID } });
    if (!user) {
      return next(createHttpError(404, "User not found"));
    }
    req.user = user;
    next();
  } catch (error) {
    return next(createHttpError(401, "Not authorized, token failed"));
  }
};

export default authMiddleware;