package br.com.mike.seguranca.modelo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jetbrains.annotations.Nullable;

import java.io.Serializable;

public class Autenticacao implements Serializable {

    private String identificador;
    private String token;

    public Autenticacao() {
    }

    public Autenticacao(String identificador) {
        this.identificador = identificador;
    }

    public String getIdentificador() {
        return identificador;
    }

    public void setIdentificador(String identificador) {
        this.identificador = identificador;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String serializar() {
        try {
            ObjectMapper objectMapper =
                    new ObjectMapper().
                            setSerializationInclusion(JsonInclude.Include.NON_NULL);
            return objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException ex) {
            return null;
        }
    }

    public static @Nullable Autenticacao deserializar(String texto) {
        try {
            ObjectMapper objectMapper = new ObjectMapper().
                    setSerializationInclusion(JsonInclude.Include.NON_NULL);
            return objectMapper.readValue(texto, Autenticacao.class);
        } catch (JsonProcessingException ex) {
            return null;
        }
    }
}
