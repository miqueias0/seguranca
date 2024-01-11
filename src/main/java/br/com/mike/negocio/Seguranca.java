package br.com.mike.negocio;

import br.com.mike.modelo.Autenticacao;
import br.com.mike.records.AutenticacaoRecord;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;

@Service
public class Seguranca {

    public String criarToken(String id, Integer tempoToken) throws Exception {
        Autenticacao autenticacao = new Autenticacao(id);
        if(tempoToken == null){
            return new br.com.mike.token.Seguranca().criarToken(autenticacao);
        }else {
            return new br.com.mike.token.Seguranca().criarToken(autenticacao, tempoToken);
        }

    }

    public Autenticacao validarToken(@NotNull String token) throws Exception {
        return new br.com.mike.token.Seguranca().validarToken(token);
    }

    public Autenticacao converterAtuenticacaoRecord(AutenticacaoRecord autenticacaoRecord){
        Autenticacao autenticacao = new Autenticacao();

        autenticacao.setIdentificador(autenticacaoRecord.identificador());
        autenticacao.setToken(autenticacaoRecord.token());

        return autenticacao;
    }

    public AutenticacaoRecord converterAtuenticacao(Autenticacao autenticacao){
        AutenticacaoRecord autenticacaoRecord = new AutenticacaoRecord(autenticacao.getIdentificador(), autenticacao.getToken());
        return autenticacaoRecord;
    }
}
