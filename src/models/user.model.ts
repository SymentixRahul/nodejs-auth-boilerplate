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
            error: false,
            status: 200,
            message: 'User logged in successfully',
            data: { userId: user.id, token }
          };
          return res;
        } else {
          const errorDetails = {
            error: true,
            status: 401,
            data: null,
            message: 'Password not match'
          };
          return errorDetails;
        }
      } else {
        const errorDetails = {
          error: true,
          status: 401,
          data: null,
          message: 'Login failed! User not available'
        };
        return errorDetails;
      }
    } catch (err) {
      const errorDetails = {
        error: true,
        status: 501,
        data: null,
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
      return {
        status: 409,
        error: true,
        message: 'User already exists',
        data: null
      };
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
        status: 200,
        error: false,
        message: 'User register successfully',
        data: { userId: user.id, token }
      };
      return res;
    }
  };

  public static updateUser = async (userObject: any) => {
    if (userObject.password != 'undefined' && userObject.password.length > 0) {
      userObject.password = await UserModel.hashPassword(userObject.password);
    }
    const user = await UserSchema.findOne({
      where: { id: userObject.id }
    });

    if (!user) {
      console.log('called');
      const res = {
        status: 404,
        error: true,
        message: 'User not exists',
        data: null
      };
      return res;
    } else {
      const updatedUser = await UserSchema.update(userObject, {
        where: { id: userObject.id },
        returning: true
      });
      const res = {
        status: 200,
        error: false,
        message: 'User updated successfully',
        data: updatedUser
      };
      return res;
    }
  };

  public static getUserById = async (userId: any) => {
    const user = await UserSchema.findOne({
      where: { id: userId }
    });
    if (!user) {
      const res = {
        status: 404,
        error: true,
        message: 'User not exists',
        data: null
      };
      return res;
    }
    const res = {
      status: 200,
      error: false,
      message: 'User fetch successfully',
      data: user
    };
    return res;
  };

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
