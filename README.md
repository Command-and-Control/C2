## C2 - Command and Control
## Beacon
O beacon é uma (micro)-aplicação que se conecta ao servidor e executa comandos, entre outras instruções recebidas. Pode enviar informações do sistema, executar comandos arbitrários e manipular arquivos.

### Funcionalidades Principais:
- Envio de Informações do Sistema: Periodicamente envia informações detalhadas do sistema para o servidor.
- Execução de Comandos: Executa comandos PowerShell ou CMD enviados pelo servidor.
- Manipulação de Arquivos: Pode receber e enviar arquivos para o servidor, além de executar operações de persistência no sistema.
- Comandos Suportados:
`enumerate`: Coleta e envia informações do sistema.
`::DOWNLOAD::`: Baixa um arquivo especificado pelo servidor.
`::PERSIST::`: Implementa persistência no sistema para manter o acesso.
`::LATMOVE::`: Realiza movimento lateral na rede.
`::PRIVESC::`: Tenta elevar privilégios no sistema.
`::RUNCMD::`: Executa um comando específico.

## 2. Servidor
O servidor é uma aplicação que gerencia múltiplas conexões de clientes, envia comandos e recebe dados.

### Funcionalidades Principais:
- Gestao de Sessões: Mantém uma lista de todos os clientes conectados.
- Envio de Comandos: Pode enviar comandos para um ou todos os clientes conectados.
- Recepção de Dados: Recebe dados dos clientes, como informações do sistema ou arquivos.

### Comandos Suportados:
- `security_report`: Solicita um relatorio de seguranca.
- `enumerate`: Solicita informações do sistema do cliente.
- `broadcast`: Envia um comando para todos os clientes.
- `sessions`: Lista todas as sessões de clientes ativas.
- `generate`: Gera um novo cliente (beacon) com configurações específicas.
- `listeners`: Lista todos os ouvintes de rede ativos.
- `ceate_listener`: Cria um novo ouvinte de rede.


## XorCrypt
XorCrypt é uma biblioteca de criptografia que utiliza o método XOR para criptografar e descriptografar dados. É usada tanto pelo cliente quanto pelo servidor para garantir a segurança e obfuscaação na comunicação. As strings, entre outras coisas, são todas encryptadas em compile time, sendo que são desencriptadas em runtime.

### Como Executar
- Pré-requisitos
 - Rust

### Compilar
Para compilar basta:
```
cargo build --release
```
O executável estará na pasta `target/release`

Ao iniciar o servidor, temos os diversos comando apresentados anteriormente.

## Exemplos
- Enumerar Clientes
`enumerate 0 /path/to/save.txt txt`
- Listar Sessões
`sessions`
- Interagir com uma Sessão
`sessions interact 1`
- Gerar Beacon
`generate`
- Listar Listeners
`listeners`
- Criar Listener
`create_listener 8081`
Enviar Comando de Broadcast
`broadcast "echo Hello, World!"`
- Solicitar Relatório de Segurança
`security_report 0 /path/to/report.json json`
- Sair do Servidor
`exit`
- Ajuda
`help`