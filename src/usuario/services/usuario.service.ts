import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateUsuarioDto } from '../dto/create-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Usuario } from '../entities/usuario.entity';

@Injectable()
export class UsuarioService {
  constructor(
    @InjectRepository(Usuario)
    private readonly usuarioRepository: Repository<Usuario>,
  ) {}

  async createUser(createUsuarioDto: CreateUsuarioDto): Promise<Usuario> {
    const newUser = await this.usuarioRepository.create(createUsuarioDto);
    return this.usuarioRepository.save(newUser);
  }

  findAll(): Promise<Usuario[]> {
    return this.usuarioRepository.find();
  }

  async findOnebyEmail(email: string): Promise<Usuario> {
    const usuario = await this.usuarioRepository.findOne({
      where: { email },
      select: { email: true, password: true, id: true },
    });
    return usuario;
  }

  async findOneById(id: string): Promise<Usuario> {
    return await this.usuarioRepository.findOne({
      where: { id },
    });
  }
}
