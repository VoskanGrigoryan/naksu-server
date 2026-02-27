import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserRole } from '@prisma/client';
import bcrypt from 'bcrypt';
import { TokenService } from './token/token.service';
import { GoogleService } from './google/google.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
    private readonly googleService: GoogleService,
  ) {}

  async refresh(refreshToken: string) {
    return this.tokenService.refresh(refreshToken);
  }

  async logout(refreshToken: string) {
    return this.tokenService.logout(refreshToken);
  }

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existing) throw new ConflictException('Email already used');

    const passwordHash = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.$transaction(async (tx) => {
      const createdUser = await tx.user.create({
        data: {
          email: dto.email,
          passwordHash,
        },
      });

      await tx.userRoleAssignment.create({
        data: {
          userId: createdUser.id,
          role: UserRole.MEMBER,
        },
      });

      await tx.authProvider.create({
        data: {
          userId: createdUser.id,
          provider: 'LOCAL',
        },
      });

      return tx.user.findUnique({
        where: { id: createdUser.id },
        include: { roles: true },
      });
    });

    return this.tokenService.generateTokens(user);
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      include: { roles: true },
    });

    if (!user || !user.passwordHash || !user.isActive)
      throw new UnauthorizedException();

    const valid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!valid) throw new UnauthorizedException();

    return this.tokenService.generateTokens(user);
  }

  async googleLogin(idToken: string) {
    const { email, sub } = await this.googleService.verify(idToken);

    let user = await this.prisma.user.findUnique({
      where: { email },
      include: { roles: true, authProviders: true },
    });

    if (!user) {
      user = await this.prisma.$transaction(async (tx) => {
        const newUser = await tx.user.create({
          data: { email },
        });

        await tx.userRoleAssignment.create({
          data: {
            userId: newUser.id,
            role: UserRole.MEMBER,
          },
        });

        await tx.authProvider.create({
          data: {
            userId: newUser.id,
            provider: 'GOOGLE',
            providerId: sub,
          },
        });

        return tx.user.findUnique({
          where: { id: newUser.id },
          include: { roles: true, authProviders: true },
        });
      });
    }

    if (!user || !user.isActive) {
      throw new UnauthorizedException();
    }

    return this.tokenService.generateTokens(user);
  }
}
