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
          const res = {
            message: 'User logged in successfully',
            error: false,
            data: { token, userId: user.id }
          };
          return res;
        } else {
          const errorDetails = {
            error: true,
            message: 'Password not match'
          };
          return errorDetails;
        }
      } else {
        const errorDetails = {
          error: true,
          message: 'Login failed! User not available'
        };
        return errorDetails;
      }
    } catch (err) {
      const errorDetails = {
        error: true,
        message: err
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
      return { message: 'User already exists', error: true };
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
      const res = {
        message: 'User register successfully',
        error: false,
        data: { token, userId: user.id }
      };
      return res;
    }
  };

  public static updateUser = async (userObject: any) => {
    if (userObject.password != 'undefined' && userObject.password.length > 0) {
      userObject.password = await UserModel.hashPassword(userObject.password);
    }
    return UserSchema.update(userObject, {
      where: { id: userObject.id },
      returning: true
    });
  };

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
