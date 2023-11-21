import { Controller } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { CreateUserDto, LoginUserDto, ValidateUserDto,FindUserIdDto } from '../dto/index';
import { GrpcMethod } from '@nestjs/microservices';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @GrpcMethod('AuthService', 'Register')
  register(payload: CreateUserDto) {
    return this.authService.register(payload);
  }

  @GrpcMethod('AuthService', 'Login')
  login(payload: LoginUserDto) {
    return this.authService.login(payload);
  }

  @GrpcMethod('AuthService', 'Validate')
  validate(payload: ValidateUserDto) {
    return this.authService.validate(payload.token);
  }

  @GrpcMethod('AuthService', 'findUserById')
  findUserById(payload: FindUserIdDto) {
    return this.authService.findUserbyId(payload);
  }
}
