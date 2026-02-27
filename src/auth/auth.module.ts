import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})

export class AuthModule {}
