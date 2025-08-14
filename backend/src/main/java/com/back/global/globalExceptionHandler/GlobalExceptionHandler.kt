package com.back.global.globalExceptionHandler

import com.back.global.exception.ServiceException
import com.back.global.rsData.RsData
import jakarta.validation.ConstraintViolationException
import lombok.RequiredArgsConstructor
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.validation.FieldError
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.MissingRequestHeaderException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
@RequiredArgsConstructor
class GlobalExceptionHandler {

    @ExceptionHandler(NoSuchElementException::class)
    fun handle(ex: NoSuchElementException?): ResponseEntity<RsData<Void>> =
        ResponseEntity
            .status(HttpStatus.NOT_FOUND)
            .body(RsData("404-1", "해당 데이터가 존재하지 않습니다."))

    @ExceptionHandler(ConstraintViolationException::class)
    fun handle(ex: ConstraintViolationException): ResponseEntity<RsData<Void>> {
        val message = ex.constraintViolations
            .asSequence()
            .map { violation ->
                val path = violation.propertyPath.toString()
                val field: String = path.split(".", limit = 2).getOrElse(1) { path }

                val bits = violation.messageTemplate.split(".")
                val code = bits.getOrNull(bits.size - 2) ?: "Unknown"

                "$field-$code-${violation.message}"
            }
            .sorted()
            .joinToString("\n")

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(RsData("400-1", message))
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handle(ex: MethodArgumentNotValidException): ResponseEntity<RsData<Void?>?> {
        val message = ex.bindingResult.allErrors.asSequence()
            .filterIsInstance<FieldError>()
            .map { err -> "${err.field}-${err.code}-${err.defaultMessage}" }
            .sorted()
            .joinToString("\n")

        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(RsData("400-1", message))
    }

    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun handle(ex: HttpMessageNotReadableException): ResponseEntity<RsData<Void>> =
        ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(RsData("400-1", "요청 본문이 올바르지 않습니다."))

    @ExceptionHandler(MissingRequestHeaderException::class)
    fun handle(ex: MissingRequestHeaderException): ResponseEntity<RsData<Void>> =
        ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(RsData("400-1", "${ex.headerName}-NotBlank-${ex.localizedMessage}"))

    @ExceptionHandler(ServiceException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handle(ex: ServiceException): ResponseEntity<RsData<Void>> {
        val rsData = ex.rsData

        return ResponseEntity
            .status(rsData.statusCode)
            .body(rsData)
    }
}