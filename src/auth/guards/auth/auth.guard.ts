import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Observable } from 'rxjs';
import { AuthService } from 'src/auth/auth.service';
import { JwtPayload } from 'src/auth/interfaces/jwt-payload';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor( private jwtService: JwtService, private authSevice: AuthService) {}

  async canActivate( context: ExecutionContext ): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if(!token) {
      throw new UnauthorizedException('There is no beared token in the request');
    }
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token, { secret: process.env.JWT_SEED }
      );
      const user = await this.authSevice.findUserById(payload.userId);
      if(!user || !user.isActive) throw new UnauthorizedException();
      
      request['user'] = payload;
    } catch {
      throw new UnauthorizedException('An error occurred while trying to verify the token');
    }

    return Promise.resolve(true);
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization'].split(' ') ?? [];
    return type === 'Beared' ? token : undefined;
  }
}
