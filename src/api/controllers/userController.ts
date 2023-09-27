import {Request, Response, NextFunction} from 'express';
import userModel from '../models/userModel';
import CustomError from '../../classes/CustomError';
import {validationResult} from 'express-validator';
import {OutputUser, User} from '../../interfaces/User';
import bcrypt from 'bcrypt';
import DBMessageResponse from '../../interfaces/DBMessageResponse';
const salt = bcrypt.genSaltSync(12);
// Description: This file contains the functions for the user routes
// TODO: add function check, to check if the server is alive
// TODO: add function to get all users
// TODO: add function to get a user by id
// TODO: add function to create a user
// TODO: add function to update a user
// TODO: add function to delete a user
// TODO: add function to check if a token is valid

const check = (_: Request, res: Response) => {
  res.json({message: 'Server is alive'});
};

const userListGet = async (_: Request, res: Response, next: NextFunction) => {
  try {
    const users = await userModel.find().select('-password -role');
    res.json(users);
  } catch (err) {
    next(new CustomError('Could not get users', 500));
  }
};

const userGet = async (
  req: Request<{id: string}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await userModel
      .findById(req.params.id)
      .select('-password -role');
    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }
    res.json(user);
  } catch (err) {
    next(new CustomError('Could not get user', 500));
  }
};

const userPost = async (
  req: Request<{}, {}, User>,
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

    const user = req.body;
    user.password = await bcrypt.hash(user.password, salt);
    user.role = user.role || 'user';

    const newUser = await userModel.create(user);
    const response: DBMessageResponse = {
      message: 'User created successfully',
      user: {
        user_name: newUser.user_name,
        email: newUser.email,
        id: newUser._id,
      },
    };
    res.json(response);
  } catch (err) {
    next(new CustomError('Could not create user', 500));
  }
};

const userPut = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const tokenUser: OutputUser = res.locals.user as OutputUser;
    let userId = tokenUser.id;
    if (req.params.id && res.locals.user.role.includes('admin')) {
      userId = req.params.id;
    }

    const user: User = req.body as User;
    if (user.password) {
      user.password = await bcrypt.hash(user.password, salt);
    }

    const resultUser: User = (await userModel
      .findByIdAndUpdate(userId, user, {new: true})
      .select('-password -role')) as User;
    if (!resultUser) {
      next(new CustomError('User not found', 404));
      return;
    }

    const response: DBMessageResponse = {
      message: 'User updated successfully',
      user: {
        user_name: resultUser.user_name,
        email: resultUser.email,
        id: resultUser._id,
      },
    };

    res.json(response);
  } catch (err) {
    next(new CustomError('Could not update user', 500));
  }
};

const userPutAdmin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const userId = req.params.id;
    if (!res.locals.user.role.includes('admin')) {
      next(new CustomError('Not authorized', 401));
      return;
    }

    const user: User = req.body as User;
    if (user.password) {
      user.password = await bcrypt.hash(user.password, salt);
    }

    const resultUser: User = (await userModel
      .findByIdAndUpdate(userId, user, {new: true})
      .select('-password -role')) as User;
    if (!resultUser) {
      next(new CustomError('User not found', 404));
      return;
    }

    const response: DBMessageResponse = {
      message: 'User updated successfully',
      user: {
        user_name: resultUser.user_name,
        email: resultUser.email,
        id: resultUser._id,
      },
    };

    res.json(response);
  } catch (err) {
    next(new CustomError('Could not update user', 500));
  }
};

const userDelete = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const tokenUser: OutputUser = res.locals.user as OutputUser;
    const userId = tokenUser.id;
    const resultUser: User = (await userModel.findByIdAndDelete(
      userId
    )) as User;
    if (!resultUser) {
      next(new CustomError('User not found', 404));
      return;
    }

    const response: DBMessageResponse = {
      message: 'User deleted successfully',
      user: {
        user_name: resultUser.user_name,
        email: resultUser.email,
        id: resultUser._id,
      },
    };

    res.json(response);
  } catch (err) {
    next(new CustomError('Could not delete user', 500));
  }
};

const userDeleteAsAdmin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const userId = req.params.id;
    if (!res.locals.user.role.includes('admin')) {
      next(new CustomError('Not authorized', 401));
      return;
    }

    const resultUser: User = (await userModel.findByIdAndDelete(
      userId
    )) as User;
    if (!resultUser) {
      next(new CustomError('User not found', 404));
      return;
    }

    const response: DBMessageResponse = {
      message: 'User deleted successfully',
      user: {
        user_name: resultUser.user_name,
        email: resultUser.email,
        id: resultUser._id,
      },
    };

    res.json(response);
  } catch (err) {
    next(new CustomError('Could not delete user', 500));
  }
};

const checkToken = (_: Request, res: Response, next: NextFunction) => {
  try {
    const tokenUser: OutputUser = res.locals.user as OutputUser;
    const message: DBMessageResponse = {
      message: 'Token is valid',
      user: tokenUser,
    };

    res.json(message);
  } catch (err) {
    next(new CustomError('Token is invalid', 401));
  }
};

export {
  check,
  userListGet,
  userGet,
  userPost,
  userPut,
  userPutAdmin,
  userDelete,
  userDeleteAsAdmin,
  checkToken,
};
