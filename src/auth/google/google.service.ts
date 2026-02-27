import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OAuth2Client } from 'google-auth-library';

@Injectable()
export class GoogleService {
  private readonly client: OAuth2Client;

  constructor(private config: ConfigService) {
    this.client = new OAuth2Client(this.config.get<string>('GOOGLE_CLIENT_ID'));
  }

  async verify(idToken: string) {
    const ticket = await this.client.verifyIdToken({
      idToken,
      audience: this.config.get<string>('GOOGLE_CLIENT_ID'),
    });

    const payload = ticket.getPayload();
    if (!payload?.email) {
      throw new UnauthorizedException();
    }

    return {
      email: payload.email,
      sub: payload.sub,
    };
  }
}
