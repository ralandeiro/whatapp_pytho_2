import unittest
import os
import pandas as pd
from app import app, db, Usuario, processar_upload_excel

class GymZapTestCase(unittest.TestCase):
    
    def setUp(self):
        """Configura ambiente de teste antes de cada teste"""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' # Banco em memória
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        
        with app.app_context():
            db.create_all()

    def tearDown(self):
        """Limpa ambiente após cada teste"""
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_criacao_usuario_senha_segura(self):
        """Teste se o hash de senha (Bcrypt) está funcionando (Requisito 6/PRD 9.2)"""
        u = Usuario(username='testadmin', nivel_acesso='admin')
        u.set_password('senha123')
        
        # A senha salva não pode ser igual à senha texto plano
        self.assertNotEqual(u.password_hash, 'senha123')
        # A verificação deve funcionar
        self.assertTrue(u.check_password('senha123'))
        self.assertFalse(u.check_password('senhaerrada'))

    def test_processamento_planilha(self):
        """Teste da lógica de importação de Excel (Requisito 9)"""
        # Criar um DataFrame pandas simulando um Excel
        data = {
            'Celular': ['27999991111', '27999992222', ''], # Um número vazio
            'Nome Completo': ['João Silva', 'Maria Santos', 'Sem Nome']
        }
        df = pd.DataFrame(data)
        
        # Salvar temporariamente
        filename = 'test_planilha.xlsx'
        df.to_excel(filename, index=False)
        
        # Configurar mapeamento (Layout)
        mapeamento = {'telefone': 'Celular', 'aluno': 'Nome Completo'}
        
        try:
            # Executar função core
            resultados = processar_upload_excel(filename, mapeamento)
            
            # Deve ignorar a linha sem telefone, restando 2
            self.assertEqual(len(resultados), 2)
            self.assertEqual(resultados[0]['telefone'], '27999991111')
            self.assertEqual(resultados[0]['aluno'], 'João Silva')
            
        finally:
            # Limpar arquivo
            if os.path.exists(filename):
                os.remove(filename)

    def test_rota_login_acesso(self):
        """Teste se rota protegida bloqueia acesso sem login"""
        response = self.app.get('/', follow_redirects=True)
        # Deve redirecionar para login e conter mensagem de erro ou texto da pagina de login
        self.assertIn(b'Login', response.data)

if __name__ == '__main__':
    unittest.main()