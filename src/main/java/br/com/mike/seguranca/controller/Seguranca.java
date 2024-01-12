package br.com.mike.seguranca.controller;

import br.com.mike.comum.records.AutenticacaoRecord;
import br.com.mike.comum.records.TokenRecord;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/seguranca")
public class Seguranca {

    private final br.com.mike.seguranca.negocio.Seguranca seguranca = new br.com.mike.seguranca.negocio.Seguranca();

    @GetMapping(value = "/validarToken")
    public ResponseEntity<AutenticacaoRecord> validarToken(@RequestParam("token") String token) throws Exception{
        try{
            AutenticacaoRecord autenticacaoRecord = seguranca.converterAtuenticacao(seguranca.validarToken(token));
            return ResponseEntity.ok(autenticacaoRecord);
        } catch (Exception e) {
            throw new Exception("Erro ao validar Token pelo seguinte motivo: " + e.getLocalizedMessage());
        }
    }

    @PostMapping(value = "/criarToken")
    public ResponseEntity<TokenRecord> criarToken(@RequestParam("id") String id, @RequestParam("tempoToken") Integer tempoToken) throws Exception{
        try{
            TokenRecord tokenRecord = new TokenRecord(seguranca.criarToken(id, tempoToken));
            return ResponseEntity.ok(tokenRecord);
        } catch (Exception e) {
            throw new Exception("Erro ao Criar Token pelo seguinte motivo: " + e.getLocalizedMessage());
        }
    }

    @PostMapping(value = "/atualizarToken")
    public ResponseEntity<TokenRecord> atualizarToken(@RequestParam("token") String token) throws Exception{
        try{
            TokenRecord tokenRecord = new TokenRecord(seguranca.criarToken(seguranca.validarToken(token).getIdentificador(), null));
            return ResponseEntity.ok(tokenRecord);
        } catch (Exception e) {
            throw new Exception("Erro ao Criar Token pelo seguinte motivo: " + e.getLocalizedMessage());
        }
    }
}
