import { IsUUID } from 'class-validator';

export class FindUserIdDto {
  @IsUUID()
  id: string;
}
