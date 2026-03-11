/** Configuration for a system user that can be spawned in a terminal session. */
export interface UserConfig {
  uid: number;
  gid: number;
  home: string;
}

/** Map of allowed users and their system-level configuration. */
const USERS: Record<string, UserConfig> = {
  dev: { uid: 1001, gid: 1001, home: '/home/dev' },
  devops: { uid: 1002, gid: 1002, home: '/home/devops' },
};

/** Resolves a user parameter to its config. Falls back to `dev` for unknown users. */
export function resolveUser(userParam: string): UserConfig {
  return USERS[userParam] || USERS.dev;
}
