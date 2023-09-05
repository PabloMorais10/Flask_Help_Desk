from flask import Flask, render_template, request, flash, redirect, url_for
from sqlalchemy import create_engine
import fdb
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'flamengo10'

# Configure o URI do banco de dados
db_uri = "firebird+fdb://sysdba:masterkey@localhost:3050/C:/TGA/Dados/PORTANOVO.FDB"
engine = create_engine(db_uri, echo=True, future=True)

def conectar_banco():
    try:
        con = fdb.connect(
            host='localhost',
            port=3050,
            database='C:/TGA/Dados/PORTANOVO.FDB',
            user='SYSDBA',
            password='masterkey'
        )
        print("Conexão ao banco de dados bem-sucedida.")
        return con
    except Exception as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        return None

@app.route('/cadastrar')
def index():
    return render_template('cadastro.html')

@app.route('/cadastrar', methods=['POST'])
def cadastrar():
    nome = request.form['nome']
    senha = request.form['senha']
    confirma_senha = request.form['confirma_senha']

    # Verifique se as senhas coincidem
    if senha != confirma_senha:
        flash('As senhas não coincidem. Tente novamente.', 'danger')
        return render_template('cadastro.html')

    # Conecte ao banco de dados Firebird
    conexao = conectar_banco()

    if conexao:
        try:
            cursor = conexao.cursor()

            # Verifique se o nome de usuário já existe
            cursor.execute("SELECT COUNT(*) FROM gusuarios WHERE nome = ?", (nome,))
            existe_nome = cursor.fetchone()[0]

            if existe_nome > 0:
                flash('Nome de usuário já em uso. Escolha outro.', 'danger')
                return render_template('cadastro.html')

            # Gere um salt e faça o hash da senha
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(senha.encode('utf-8'), salt)

            # Obtenha o próximo valor da sequência para idusu
            cursor.execute("SELECT MAX(idusu) FROM gusuarios")
            max_idusu = cursor.fetchone()[0]

            if max_idusu is None:
                idusu = 1
            else:
                idusu = max_idusu + 1

            # Execute a inserção com o novo valor de idusu e senha criptografada
            cursor.execute("INSERT INTO gusuarios (idusu, nome, senhanova) VALUES (?, ?, ?)", (idusu, nome, hashed_password))

            # Commit para salvar as alterações no banco de dados
            conexao.commit()

            # Feche o cursor e a conexão
            cursor.close()
            conexao.close()

            flash('Cadastro concluído com sucesso!', 'success')
            return render_template('cadastro.html')

        except Exception as e:
            flash(f"Erro ao cadastrar no banco de dados: {e}", 'danger')
            return render_template('cadastro.html')

    flash("Erro ao conectar ao banco de dados.", 'danger')
    return render_template('cadastro.html')

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    nome = request.form['nome']
    senha_fornecida = request.form['senha']

    # Verifique as credenciais do usuário no banco de dados
    conexao = conectar_banco()

    if conexao:
        try:
            cursor = conexao.cursor()

            # Execute uma consulta para obter a senha armazenada no banco de dados
            cursor.execute("SELECT senhanova FROM gusuarios WHERE nome = ?", (nome,))
            senha_hash_db = cursor.fetchone()

            if senha_hash_db:
                senha_hash_db = senha_hash_db[0].encode('utf-8')  # Codifique a senha do banco de dados
                # Verifique se a senha fornecida corresponde à senha armazenada no banco de dados
                if bcrypt.checkpw(senha_fornecida.encode('utf-8'), senha_hash_db):
                    flash('Login bem-sucedido!', 'success')
                    return render_template('dashbord.html')  # Redirecione para a página de dashboard após o login bem-sucedido
                else:
                    flash('Credenciais inválidas. Tente novamente.', 'danger')
            else:
                flash('Nome de usuário não encontrado.', 'danger')

            # Feche o cursor e a conexão
            cursor.close()
            conexao.close()

        except Exception as e:
            flash(f"Erro ao verificar as credenciais: {e}", 'danger')

    flash("Erro ao conectar ao banco de dados.", 'danger')
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)

