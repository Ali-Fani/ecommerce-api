import { Controller } from '@nestjs/common';
import { Post, Body } from '@nestjs/common/decorators';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/auth-login.dto';
import { RegisterDto } from './dto/auth-register.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }
}
