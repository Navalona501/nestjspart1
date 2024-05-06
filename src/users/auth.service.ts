import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";
import { scrypt as _scrypt, randomBytes } from "crypto";
import { promisify } from "util";

import { UsersService } from "./users.service";

const scrypt = promisify(_scrypt);

@Injectable()
export class AuthService{
    constructor(private usersService: UsersService){}


    async signup(email: string, password: string){
        // See if email is in use
        const users = await this.usersService.find(email);
        if(users.length){
            throw new BadRequestException('email in use');
        }

        // Hash the users password
        const salt = randomBytes(8).toString('hex');

        const buf = (await scrypt(password, salt, 64)) as Buffer;

        const hashedPassword = buf.toString('hex') + '.' + salt;

        // Create a new user and save it in the database
        const user = await this.usersService.create(email, hashedPassword);

        // return the user
        return user;
    }

    async signin(email: string, password: string){
        const user = await this.usersService.find(email);
        if(!user || user.length === 0){
            throw new NotFoundException('user not found');
        }
        console.log("user is working " + user[0].password + " " + password);

        const [storedHash, salt] = user[0].password.split('.');

        const hash = (await scrypt(password, salt, 64) as Buffer).toString('hex');

        if(storedHash !== hash){
            throw new BadRequestException('bad password');
        }

        return user[0];
    }
}