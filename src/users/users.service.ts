import { Injectable, NotFoundException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';

@Injectable()
export class UsersService {

    constructor(@InjectRepository(User) private repo: Repository<User>){
    }

    create(email: string, password: string){
        const user = this.repo.create({email, password});
        console.log("created user", user);
        return this.repo.save(user);
    }

    async findOne(id: number){
        if(!id){
            return  null;
        }
        return await this.repo.findOneBy({id});
    }

    async find(email: string){
        return await this.repo.findBy({ email });

    }

    async update(id: number, attrs: Partial<User>){
        const user = await this.findOne(id);
        if(!user){
            throw new Error('user not found');
        }
        Object.assign(user, attrs);
        return this.repo.save(user);
    }

    async remove(id: number){
        const user = await this.findOne(id);
        if(!user){
            throw new NotFoundException('user not found');
        }
        return this.repo.remove(user);
    }
}
