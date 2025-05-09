package com.imperialgrand.backend.responseWrapper;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponse<T> {
    private boolean success;
    private T data;
    private String message;

    public ApiResponse(T data, String message) {
        this.success = true;
        this.data = data;
        this.message = message;
    }
}
