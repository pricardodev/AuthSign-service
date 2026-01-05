# CMS EMBEDDER PyTHON SERVICE

Esse serviço serve, exclusivamente, para preparar um documento PDF para assinatura e inserir um CMS na estrutura desse PDF preparado.

## Como iniciar o projeto?

#### Primeiro, deve-se iniciar o env virtual. Para isso, execute os camandos abaixo:

``` 
python3 -m venv venv
source venv/bin/activate ou .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

#### Após isso, execute o comando abaixo para iniciar o server:

```
flask --app pdf_sigining_server:app run ou flask --app pdf_sigining_server:app run --port=5001
```

#### Rotas para testar se op serviço esta funcionando, abaixo exemplo de url e porta

```
http://localhost:5001/health

{
	"checks": {
		"api": "operational",
		"memory": "stable",
		"storage": "ok"
	},
	"service": "AuthSign PDF Signing Service",
	"status": "UP",
	"timestamp": "2026-01-05T19:50:17.494233Z"
}

http://localhost:5001/status

{
	"status": "ok"
}
```

