import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import bcrypt from 'bcrypt';
import { RefreshToken } from '@prisma/client';
import ms, { StringValue } from 'ms';

@Injectable()
export class TokenService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async generateTokens(user: any) {
    const refreshExpires = this.config.get<string>('JWT_REFRESH_EXPIRES');

    if (!refreshExpires) {
      throw new Error('JWT_REFRESH_EXPIRES not defined');
    }

    const expires = new Date(Date.now() + ms(refreshExpires as StringValue));
    const payload = {
      sub: user.id,
      email: user.email,
      roles: user.roles.map((r) => r.role),
    };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.config.get('JWT_ACCESS_SECRET'),
      expiresIn: this.config.get('JWT_ACCESS_EXPIRES'),
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.config.get('JWT_REFRESH_SECRET'),
      expiresIn: this.config.get('JWT_REFRESH_EXPIRES'),
    });

    const hashed = await bcrypt.hash(refreshToken, 10);

    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: hashed,
        expiresAt: expires,
      },
    });

    return { accessToken, refreshToken };
  }

  async refresh(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
      });

      const tokens = await this.prisma.refreshToken.findMany({
        where: {
          userId: payload.sub,
          revoked: false,
          expiresAt: { gt: new Date() },
        },
      });

      let validToken: RefreshToken | null = null;

      for (const t of tokens) {
        const match = await bcrypt.compare(refreshToken, t.tokenHash);
        if (match) {
          validToken = t;
          break;
        }
      }

      if (!validToken) throw new UnauthorizedException();

      // ROTATION: revoke old refresh token immediately
      await this.prisma.refreshToken.update({
        where: { id: validToken.id },
        data: { revoked: true },
      });

      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
        include: { roles: true },
      });

      if (!user || !user.isActive) throw new UnauthorizedException();

      // generate new access + refresh token (new refresh stored in DB)
      return this.generateTokens(user);
    } catch {
      throw new UnauthorizedException();
    }
  }

  async logout(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
      });

      const tokens = await this.prisma.refreshToken.findMany({
        where: {
          userId: payload.sub,
          revoked: false,
        },
      });

      for (const t of tokens) {
        const match = await bcrypt.compare(refreshToken, t.tokenHash);
        if (match) {
          await this.prisma.refreshToken.update({
            where: { id: t.id },
            data: { revoked: true },
          });
          break;
        }
      }

      return { success: true };
    } catch {
      throw new UnauthorizedException();
    }
  }
}
