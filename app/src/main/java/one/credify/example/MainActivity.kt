package one.credify.example

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import one.credify.crypto.KeyCreator

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        KeyCreator().createSigningKey()
    }
}