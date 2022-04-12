import { Router, Request, Response, Express } from 'express';
import { PassportStatic } from 'passport';

const uploadFileMiddleware = require('../middleware/upload');

const router = Router();

import { UserController } from '../controllers';

module.exports = (app: Express, passport: PassportStatic) => {

  router.post(
    '/register',
    uploadFileMiddleware.single('image'),
    UserController.signup
  );

  router.get('/login', UserController.login);

  return router
};

export default router;
