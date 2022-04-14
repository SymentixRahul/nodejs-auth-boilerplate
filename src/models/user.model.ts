import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import { UserSchema } from '../schemas';
import config from '../../config';

export default class UserModel {
  public static login = async (credentials: {
    email: string;
    password: string;
  }) => {
    try {
      const user = await UserSchema.findOne({
        where: { email: credentials.email }
      });
      if (user && user.password) {
        const comparePass = bcrypt.compareSync(
          credentials.password,
          user.password
        );
        if (comparePass) {
          const token = jwt.sign(
            {
              id: user.id,
              first_name: user.first_name,
              last_name: user.last_name,
              email: user.email,
              role: user.role
            },
            config.ENCRYPTION_KEY,
            { expiresIn: '7d' }
          );
          return { token };
        } else {
          const errorDetails = {
            code: 401,
            error: 'UNAUTHORIZED',
            originalInfo: 'Login failed!'
          };
          return errorDetails;
        }
      } else {
        const errorDetails = {
          code: 401,
          error: 'UNAUTHORIZED',
          originalInfo: 'Login failed!'
        };
        return errorDetails;
      }
    } catch (err) {
      const errorDetails = {
        code: 500,
        error: 'SERVER_ERROR',
        originalInfo: err
      };
      return errorDetails;
    }
  };

  public static signup = async (userObject: any) => {
    const userExist = await UserSchema.findOne({
      where: {
        email: userObject.email,
        username: userObject.username
      }
    });
    if (userExist) {
      return 'user already exists';
    } else {
      if (
        userObject.password != 'undefined' &&
        userObject.password.length > 0
      ) {
        userObject.password = await UserModel.hashPassword(userObject.password);
      }
      if (!userObject.username) {
        userObject.username = userObject.first_name + ' _ ' + Date.now();
      }
      const user = await UserSchema.create(userObject);
      const token = jwt.sign(
        {
          id: user.id,
          first_name: user.first_name,
          last_name: user.last_name,
          email: user.email,
          role: user.role
        },
        config.ENCRYPTION_KEY,
        { expiresIn: '7d' }
      );
      return { token };
    }
  };

  public static updateUser = async (userObject: any) =>
    UserSchema.update(userObject, {
      where: { id: userObject.id },
      returning: true
    });

  public static getUserById = async (userId: any) =>
    UserSchema.findOne({
      where: { id: userId }
    });

  private static hashPassword = async data => {
    const password = data;
    const saltRounds = 10;
    const hashedPassword = await new Promise((resolve, reject) => {
      bcrypt.hash(password, saltRounds, function(err, hash) {
        if (err) reject(err);
        resolve(hash);
      });
    });
    return hashedPassword;
  };

  private static generatePassword() {
    var length = 6,
      charset = 'abcdefghijklmnopqrstuvwxyz123456789',
      retVal = '';
    for (var i = 0, n = charset.length; i < length; ++i) {
      retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    return retVal;
  }
}
