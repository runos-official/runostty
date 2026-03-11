import type { UserConfig } from './users';

/** Hono environment type providing typed context variables across routes. */
export type AppEnv = {
  Variables: {
    userCfg: UserConfig;
    userName: string;
  };
};
