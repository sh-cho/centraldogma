import { UserAndTimestamp } from 'dogma/common/UserAndTimestamp';

export interface IpAccessControlRule {
  action: 'ALLOW' | 'DENY';
  cidr: string;
  description?: string;
}

export interface TokenDto {
  appId: string;
  secret?: string;
  systemAdmin: boolean;
  creation: UserAndTimestamp;
  deactivation?: UserAndTimestamp;
  ipAccessControlRules?: IpAccessControlRule[];
}
