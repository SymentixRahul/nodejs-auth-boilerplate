import { Request, Response, NextFunction } from 'express';
export const isLoggedIn = (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated() && req.user['role'] === 'admin') return next();
  res.redirect('/login');
};
