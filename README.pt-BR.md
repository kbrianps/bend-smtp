# bend-smtp

[English](README.md) · Português

Cliente SMTP em [Bend 2](https://github.com/bendlang/bend), com TLS, e um servidor de teste que só grava as mensagens. Responde à issue [lilalittle/bend-packages#42](https://github.com/lilalittle/bend-packages/issues/42).

    bend send.bend -o send
    SMTP_PASSWORD=... ./send --host smtp.gmail.com --user eu@gmail.com \
      --from "Brian <eu@gmail.com>" --to "Ana <ana@x.com>, bia@y.com" \
      --cc c@z.com --bcc d@w.com --subject "Relatório" --body "texto" \
      --html-file corpo.html --attach relatorio.pdf --attach foto.jpg \
      --header "X-Campaign: outubro"

    # com OAuth 2 (Gmail, Outlook) em vez de senha:
    SMTP_OAUTH_TOKEN=ya29... ./send --host smtp.gmail.com --user eu@gmail.com ...

    bend sink.bend -o sink
    ./sink PORT DIR                          # grava cada mensagem em DIR/N.eml
    ./sink PORT DIR tls CERT KEY             # TLS implícito
    ./sink PORT DIR starttls CERT KEY        # STARTTLS, exigido antes do MAIL

    ./test.sh                                # leis + 83 checagens (BEND=caminho do bend)

Opções do `send`:
- **destinatários:** `--to`, `--cc`, `--bcc` e `--reply-to` aceitam listas como se escreve (`"Silva, Ana" <ana@x.com>, bia@y.com`). Bcc recebe o RCPT mas nunca aparece no cabeçalho; endereço repetido recebe um RCPT só
- **corpo:** `--body`/`--body-file` (texto) e `--html`/`--html-file` (vão juntos como alternativas); `--attach` (repete; até 25 MiB por arquivo)
- **cabeçalhos próprios:** `--header "Nome: valor"` (repete). Os que o cliente já escreve (Subject, From, Content-Type...) são recusados
- **uma mensagem por destinatário:** `--individually` manda uma cópia para cada `--to`, cada um vendo só a si, todas na mesma conexão
- **depuração:** `--debug` mostra a conversa (`C:`/`S:`) no stderr, com credenciais como `(secret)` e o corpo só como tamanho
- **DKIM:** `--dkim-domain D --dkim-selector S --dkim-key chave.pem` assina a mensagem (RSA ou Ed25519). `--dkim-canon` escolhe a forma do cabeçalho e do corpo (`relaxed/relaxed` é o padrão; também `relaxed/simple`, `simple/relaxed`, `simple/simple`). From, To, Cc, Subject, Date, Reply-To e Message-ID são sobreassinados, para que um cabeçalho acrescentado no caminho quebre a assinatura (`--dkim-no-oversign` desliga). Chave que não abre ou não assina interrompe o envio
- **aviso de entrega (DSN):** `--notify never|success,failure,delay`, `--ret full|hdrs`, `--envid ID`; só vai se o servidor anuncia DSN
- **conexão:** `--tls starttls` (padrão, porta 587), `tls` (implícito, 465) ou `plain` (25); `--port`; `--cafile` (confiar numa CA própria); `--cert`/`--key` (certificado de cliente); `--proxy socks5://[usuário:senha@]host[:porta]` ou `http://...` (HTTP CONNECT); uma URL de proxy que não dá para ler é erro, nunca conexão direta; `--lmtp`; `--helo`. PIPELINING é usado sozinho quando o servidor anuncia (`--no-pipelining` desliga); `--chunking` manda por BDAT quando anunciado
- **AUTH:** `--user` e `--auth plain|login|cram-md5|xoauth2|oauthbearer` (sem `--auth`, escolhe pelo que o servidor oferece: OAuth se houver token, senão PLAIN, LOGIN, CRAM-MD5). Segredos só pelo ambiente: `SMTP_PASSWORD` ou `SMTP_OAUTH_TOKEN`

Saída: 0 entregue a todos; 3 entregue em parte (um destinatário recusado, ou só algumas das mensagens); 1 nada enviado; 2 uso errado.

Como biblioteca, o ponto de entrada é `Smtp.send_many(opts, mensagens)` em `smtp.bend` (ou `Smtp.send_mail` para uma só): devolve um `Batch` com o resultado de cada mensagem, na ordem, e o erro que encerrou a conexão, se houve.

Só funciona no build nativo (`-o send`): o Bend também roda programas em JS (`bend send.bend` sem `-o`), mas a rede e o TLS aqui são efeitos em C, e o lado JS responde "não suportado".

## RFCs

| RFC | O que cobre |
|---|---|
| 5321 SMTP | várias mensagens por conexão, uma transação cada, com RSET depois de uma que parou no meio; um destinatário recusado não derruba os outros (o 421 sim); diálogo, EHLO com fallback para HELO (HELO sempre com domínio, nunca literal), dot-stuffing, CRLF, linhas de comando até 512 octetos, timeouts da seção 4.5.3.2, QUIT esperando o 221, QUIT depois de qualquer recusa |
| 3207 STARTTLS | EHLO de novo depois do TLS; recusa dados que chegam antes do handshake (injeção); sem STARTTLS anunciado, não cai para texto aberto |
| 8314 TLS implícito | porta 465; TLS 1.2 ou mais, certificado e nome verificados (OpenSSL, carregado em runtime) |
| 4954 / 4616 AUTH | PLAIN (com continuação 334 quando passa de 512 octetos) e LOGIN; nunca sem TLS; um 334 de erro depois da resposta é encerrado com `*` |
| 7628 OAUTHBEARER, XOAUTH2 | OAuth 2 com o token de acesso; o 334 de erro (JSON em base64) é decodificado e respondido como cada um pede (`^A` ou linha vazia); vetores do Google e da RFC nas leis |
| 1870 SIZE | declara `SIZE=` no MAIL e recusa antes de enviar o que não cabe |
| 5322 mensagem | Date (UTC), From, To, Cc, Reply-To (dobrados, um endereço por linha), Subject, Message-ID; Bcc nunca escrito; só Bcc gera `To: undisclosed-recipients:;`; nomes como átomos, string entre aspas ou RFC 2047; linhas até 998 |
| 2046 multipart | texto + HTML em `multipart/alternative` (texto primeiro); com anexos, dentro de `multipart/mixed`; boundary que nenhuma parte contém |
| 2183 / 2231 anexos | `Content-Disposition: attachment`; nome fora do ASCII só na forma estendida (`filename*=UTF-8''...`), como o pacote `email` do Python escreve |
| 2045 / 2047 MIME | corpo 7bit quando é ASCII com linhas curtas, senão base64 de UTF-8 com CRLF; assunto fora do ASCII em encoded words de até 75 caracteres, dobrados |
| 2920 PIPELINING | MAIL, os RCPT e o DATA numa escrita só, quando anunciado; se o MAIL ou todos os RCPT falham, as respostas pendentes são consumidas e um 354 indevido é encerrado com mensagem vazia |
| 3030 CHUNKING | `BDAT n LAST` com o tamanho exato, sem dot-stuffing |
| 3461 DSN | `RET`, `ENVID` (xtext), `NOTIFY` e `ORCPT`, só com DSN anunciado |
| 2033 LMTP | `LHLO` e uma resposta final por destinatário |
| 2195 CRAM-MD5 | MD5 e HMAC-MD5 em Bend puro, com os vetores das RFCs 1321 e 2195 nas leis; só sob TLS |
| 1928 / 1929 SOCKS5 | o destino vai como nome (o proxy resolve o DNS); usuário e senha opcionais |
| 9110 9.3.6 CONNECT | túnel por proxy HTTP, com credenciais Basic (RFC 7617) opcionais |
| 6376 / 8463 DKIM | formas relaxed e simple, rsa-sha256 ou ed25519-sha256; todos os cabeçalhos da mensagem assinados, os principais sobreassinados (5.4); exemplo da RFC nas leis; verificado nos testes por uma implementação independente (e pelo dkimpy, se instalado) |
| 4648 base64 | vetores oficiais nas leis |
| 6531 / 6532 SMTPUTF8 | endereço com acento na parte local vai com `SMTPUTF8` (e `BODY=8BITMIME` quando há); servidor sem a extensão recebe recusa antes do MAIL |
| 3492 / 5890 punycode | domínio com acento vira A-label (`xn--...`), e a mensagem continua ASCII |

Sem endereço com acento na parte local, a mensagem sai toda em 7 bits e não depende de 8BITMIME nem de SMTPUTF8. Endereços são dot-atom (`local@domínio`); aspas e rotas são recusadas antes de conectar.

## Arquivos

- `net.c` / `net.bend`: conexão com DNS (IPv4 e IPv6), TLS que pode começar no meio da conversa, envio, leitura com prazo
- `text.bend`, `reply.bend`, `mime.bend`: linhas, respostas, base64 (ida e volta), UTF-8, Date, RFC 2047, corpo, multipart, anexos
- `smtp.bend`: o cliente; `send.bend`: a linha de comando
- `idna.bend`: punycode e A-labels
- `addr.bend`: endereços, mailboxes com nome, leitura e escrita de listas
- `sink.bend`: o servidor de teste (máquina de estados pura, com TLS e STARTTLS); `tests/server.py`: servidor de teste roteirizável (AUTH, recusas, injeção, SMTPUTF8)
- `md5.bend`: MD5 e HMAC-MD5 (só para CRAM-MD5); `dkim.bend`: canonicalização e o campo DKIM-Signature
- `LAWS.bend` / `PROOF.bend`: leis e provas
- `tests/certs/`: CA, certificados de servidor e de cliente e chaves DKIM **só de teste** (chaves privadas inclusas de propósito)
- `tests/socks.py` e `tests/httpproxy.py`: proxies de teste; `tests/dkim_verify.py`: verificador de DKIM

## Desempenho

Strings no Bend são listas encadeadas, então um anexo ocupa uns 55 bytes de RAM por byte: 10 MB levam ~1 s e ~570 MB. Tudo que percorre a mensagem é recursão de cauda (uma recursão aninhada custaria um quadro por caractere: 700 MB a mais em 2 MB de anexo).

## Deixado de fora de propósito

- a tag `l=` do DKIM (assinar só o começo do corpo): deixa qualquer um acrescentar conteúdo a uma mensagem assinada (RFC 6376 8.2)
- proxy `https://` (TLS até o proxy): recusado com erro

## Falta

- [ ] obter e renovar o token OAuth (o `send` usa um token de acesso pronto)
- [ ] BINARYMIME e BDAT em vários pedaços (vai um pedaço só)

- [ ] o mapeamento completo do IDNA2008 (normalização Unicode, maiúsculas fora do ASCII): o domínio é convertido como foi escrito
- [ ] o backend JS
- [ ] publicar no hub
