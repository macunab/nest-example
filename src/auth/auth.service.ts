import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';

import { CreateAuthDto, UpdateAuthDto, LoginDto } from './dto';
import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { JwtService } from '@nestjs/jwt';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name ) private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create(createAuthDto: CreateAuthDto): Promise<User> {
    
    try {
      const { password, ...userData } = createAuthDto;

      const newUser = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData
      });
      await newUser.save();
      delete newUser.password;
      console.table(newUser);
      return newUser;
    } catch(error) {
      if(error.code === 11000) {
        throw new BadRequestException(`${createAuthDto.email} already exist!`);
      }
      throw new InternalServerErrorException('Something terrible happen!!');
    }
  }

  async register(createAuthDto: CreateAuthDto): Promise<LoginResponse> {

    const user = await this.create(createAuthDto);
    delete user.password;
    return {
      user,
      token: this.getJwt({ userId: user._id })
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if(!user) {
      throw new UnauthorizedException('Not valid credentials');
    }

    if(!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credentials');
    }

    delete user.password;
    return {
      user,
      token: this.getJwt({ userId: user.id })
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findUserById(id: string) {
    return this.userModel.findById(id);
  }

  findOne(id: number) {
    return '';
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwt(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
