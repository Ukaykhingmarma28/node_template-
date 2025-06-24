import { Response, NextFunction } from "express";
import { AuthRequest } from "./auth";
import createHttpError from "http-errors";

const isAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.role === "admin") {
    return next();
  }
  return next(createHttpError(403, "Forbidden: Admins only"));
};

export default isAdmin; 