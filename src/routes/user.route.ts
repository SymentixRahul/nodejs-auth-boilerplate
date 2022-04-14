import { Router, Request, Response, Express } from 'express';
import { PassportStatic } from 'passport';

const uploadFileMiddleware = require('../middleware/upload');

const router = Router();

import { UserController } from '../controllers';

module.exports = (app: Express, passport: PassportStatic) => {
  
  router.post('/login', UserController.login);

  router.post(
    '/register',
    uploadFileMiddleware.single('image'),
    UserController.signup
  );

  router.patch(
    '/',
    uploadFileMiddleware.single('image'),
    UserController.signup
  );

  router.get('/:id', UserController.getUserById);

  return router;
};

export default router;
