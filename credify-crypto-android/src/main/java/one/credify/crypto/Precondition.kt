package one.credify.crypto

internal fun requireStringNotEmpty(value: String?, lazyMessage: () -> Any): String {
    if (value.isNullOrBlank()) {
        throw IllegalArgumentException(lazyMessage().toString())
    } else {
        return value
    }
}