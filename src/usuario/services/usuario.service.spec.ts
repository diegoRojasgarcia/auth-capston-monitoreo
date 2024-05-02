import { Test, TestingModule } from '@nestjs/testing';
import { UsuarioService } from './usuario.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Usuario } from '../entities/usuario.entity';

describe('UsuarioService', () => {
  let service: UsuarioService;

  const mockUsuarioRepository = {
    create: jest.fn().mockImplementation((dto) => dto),
    save: jest
      .fn()
      .mockImplementation((Usuario) =>
        Promise.resolve({ id: Date.now(), ...Usuario }),
      ),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsuarioService,
        {
          provide: getRepositoryToken(Usuario),
          useValue: mockUsuarioRepository,
        },
      ],
    }).compile();

    service = module.get<UsuarioService>(UsuarioService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should create a new user record and return that', async () => {
    expect(
      await service.createUser({
        nombre: 'testuser',
        email: 'test@gmail.com',
        password: 'Vgryq178',
      }),
    );
  });
});
