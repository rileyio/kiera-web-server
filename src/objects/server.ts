import { Request } from 'express';

export interface RequestExtended extends Request {
  isAuthenticated: () => boolean;
  user: {
    userID: string;
    session: string;
  };
}
