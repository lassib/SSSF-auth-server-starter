import {Request, Response, NextFunction} from 'express';
import {validationResult} from 'express-validator';
import CustomError from '../../classes/CustomError';
import userModel from '../models/userModel';
import {User} from '../../interfaces/User';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import LoginMessageResponse from '../../interfaces/LoginMessageResponse';

// TODO: Create login controller that creates a jwt token and returns it to the user
const login = async (
  req: Request<[], {}, {username: string; password: string}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const errorMessage = errors
        .array()
        .map((x) => x.msg)
        .join(', ');
      next(new CustomError(errorMessage, 400));
      return;
    }

    const {username, password} = req.body;
    const user: User = (await userModel.findOne({email: username})) as User;

    if (!user) {
      next(new CustomError('Invalid username or password', 400));
      return;
    }

    if (!(await bcrypt.compare(password, user.password))) {
      next(new CustomError('Invalid username or password', 400));
      return;
    }

    const token = jwt.sign(
      {id: user._id, role: user.role},
      process.env.JWT_SECRET as string
    );

    const message: LoginMessageResponse = {
      message: 'Login successful',
      user: {
        user_name: user.user_name,
        email: user.email,
        id: user._id,
      },
      token: token,
    };

    res.json(message);
  } catch (err) {
    next(new CustomError('Login not successful', 500));
  }
};

export {login};
