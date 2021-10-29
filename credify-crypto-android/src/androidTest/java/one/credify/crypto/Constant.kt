package one.credify.crypto

object Constant {
    const val ENCRYPTION_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6xGr1bqTn/hu1PN6IdEy\n" +
            "iytFPvQXWOHIDwnuuoMi6HWPTRe/q/TYGR5bEjml10whCTqPP62/iRVt+K5pkSAq\n" +
            "epoXgf3R8LltVU4ESu11tYW/A4QPBqJTMHS3zx62iLiaE67XYMcxF0jTh9HnJhOC\n" +
            "nRw7z9f4+/VRd0TrjYeptsdjHl+YqS9bym/ZTZtfGfnMFvIjfdNKFD4dtQ3G8kuA\n" +
            "VH0rHXDq4M86GZ+3WpgEAHZSLqav1geOwJDlxoDoKwLI1ca1wJDjbe24vOzmvxyJ\n" +
            "75Xh0Fhus9rK8L0/t3Ptwg1C6JKLuNmbprp6+qvs4/8heLURlDmoLZDGdkkeA1W0\n" +
            "Ys99wTU/D+eB7eWAMUPHKvesoF8AF58+pzUg7EtPUtgNiy/24888zVSRk8Skp8Qt\n" +
            "Tf4xv5KlJu4s696tbEEKjU+QucpQ5/+QfoGUvOFdoj/j92tsKnfzz3kC8d15mNex\n" +
            "k3x8nws8HZtLvpUhLLvLCekoKYsQQkrgsT6LgvdJEqyNXeMncSUQj4VH46L3Cqaq\n" +
            "eMJSyx0zUd1hzJQ0l+adgxCYYXrt9qYYkauJzabO1htiBUJZNxuuu0K1tAAe5dBV\n" +
            "q2G45EPi7us27mGTUH/vu1nNb4wztoBDb40Ehjjfbuidz+Hk7zE8oexHiAaXFFXI\n" +
            "Bo7iHDNn/q58akCJ6edjGUECAwEAAQ==\n" +
            "-----END PUBLIC KEY-----"
    
    const val ENCRYPTED_ENCRYPTION_PRIVATE_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
            "MIIJuDBiBgkqhkiG9w0BBQ0wVTA0BgkqhkiG9w0BBQwwJwQQYxN/qFh81JiFKQ0u\n" +
            "SATBiAICJxACASAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEP/lYuBuPTaF\n" +
            "8rSicWnNYxgEgglQMw4WYGzjO050piL+QbsU/sAOC4NtyjwMAWHS2El3A6eONDIp\n" +
            "R2/D1KTTf6EXR0HS6TA5n66l9mDnnbQ+vJEjyiDqbZvJtx+Aw3cATw8TwsCMnjN2\n" +
            "SBB6iVvuEyVuTTVxXds9tFSObfd1+1U1Os1N0aQPaWaAH96jpBLCJ/l9/W4bkL0w\n" +
            "rR3HxoRqNs4aUviHVCC/sK/h8ol3JRuoMNCMMAPt+SF4sgeyMDkw5d1+fYNaG83f\n" +
            "8QdCHypDNmgxRZtur/4sjXG1qlYdEp8Hq/CvbBjWTGawyk89VFzqWYQ9QotDNgLZ\n" +
            "8Ta6IOI/HZ7C75gqP6WA0OgT3V6rBVHxe8xB0bgRn5dAJ/sxUAu4FoWcE2OLlrXs\n" +
            "JEcKHlqNmCPkAeJhMgmkkcJ+q/d4eJSNFpmZpMCq1cOKFSBBFHIha4GV5b6HX65z\n" +
            "bftLmm0nVfmKO7WMDpJYXVqclPQD8WmedRAqP6wf/HZBfF51hhhvP3BrqoTvHiNp\n" +
            "lmzHhZ5q8uVLn4ugQyuphWirTrqTRS2aYS0UfHGg5pk/ab9ZUxPWkrA975jR5Hnp\n" +
            "lKLRTnQOKRplmWxH60+jcQwURSk0Sc8ZWmw70caKTWC6pafoI7CH6+qNJ+H8wySj\n" +
            "eLFFPE7Gqcd/LGWDStKKw9ltQV1RnYO0YzH1q9Te+LrzTOPsTNjWtBmxEPxjsoQt\n" +
            "h1rAdzMsbe8cfzvwHFlDqDy8HAwyw4iYGnOlRfwN6vUWfgPc8Kz3u9bm4MbRvNRs\n" +
            "4eelnqh152Ok5e4DIr+JHz6MeAM3fD364KVU7wzoK8GemUo4xYlEiXHLSYfYIMME\n" +
            "aNc4cg0jlteMRXYb/2BQ3STbbNCZjgNKuiUOk+0cJdcHjelIQLknLbZ0WeldmQJA\n" +
            "okF2+hV+Pm2JNbvIYyv/AgtBp4oXNFPk67rm1C+4hzXnugGkygyR22SXTu6CuGYK\n" +
            "8cGe8nJZcv95sGlhuJ6dLSuiwFD6rPNvghsDhc5WOlTke7mb4i2pBECaoN9NRL7q\n" +
            "8fepZyrfdwZCNKGlAFyjFavKFgTcb/rYHY1YeZm9nwj5MaBg9/LSRpzCo7/gIHU9\n" +
            "/HwUC1UG5G7fzXOkaz2fSlYfH0tV6BvR2I2RYJtlm+SLumdNel8xPB+uDApOCy56\n" +
            "LzL0E/Pd4fkN1j/LiE5CE6dGbRgfNfelU8GeuidF+lirKT65Ble6KZl9p9bRxbPr\n" +
            "xtnhtrrahW2S6hrv61Y+LUBkbMz2LQQybgICRiIzwP+UxPl4VSA0OkaLaXSRfylU\n" +
            "WwXMnAVAep4plXNP9xXFX9K0U8AyUUJ7yHPMUYcBNqLSZabU3ZNwWsUicyCuFLw1\n" +
            "pDa46E1/ni5OJ0mMJvDvk9zp3lFpADd84fezPjbNEP9ZrA1RpbMFNOCxcFy61QDy\n" +
            "ZJU91okbMiEuxZ6D7aWNfE9YVK+xmCgbZ5QCpPnEinTwu3u1nvCZFt65W4JepQ57\n" +
            "vQY0GoC0OaRd/yOvidb88gqXh3Qpn2Q675JGYvj8Zas9Giyzxc/Nb68i7/TT0t/N\n" +
            "kZB1Pf5tCU353WxwzCAjE+CWc5ojNTOjv65pZsSuv5tFnjjCM+H8YiUDmOA/0niK\n" +
            "UG89AdHqtKA+/6OvBnt9LDSlUseslYMjznpy0e09JcmFAFHWXXSggiTvuv4vt58U\n" +
            "0FV76OTS8/qgHYJL+hc1JlMdH4MuMx4lIuZL24tGZppUS/BAm6mFzVXZKrMvzEvC\n" +
            "UYNU9YEeOH24EOUVHimu5Tx0K+aWL3FicxFlKXkEm/2JbF+Ia57rpp3d8PjEG1lV\n" +
            "Xr2vYCblurrZzSUZNKfBMRWQURedMa+o+X4sxgXPDRgTKToADdKtgXuAq9PNMyAY\n" +
            "TRAEJtyyOVGB9MYMWIqCmPQzCD6C0HlDz7c0fsa9CGbYWtUoDhFl4shfeZmRqDQr\n" +
            "s3EGR7yX1KYkCGfDkYhMMM/DacqpPTrNtE/4GhyXel0PxJy3O1P6+5j989CzoByr\n" +
            "9ODINarElqHhCN7BfPK6ic4XPZuA6DIk5Og35CL/Ovbi5cey4Dool2MvKwXkYRci\n" +
            "AwCp2iquBus+/nPvAiZXVdT97VJy5D4D/YvOtop9ntZ4chqt332lv75s3L7tGwZ8\n" +
            "V6w/xrIpptsJXW/bY2ANOeCedOj8+AduM0aYLYmghL7dbu1E+6666/gJXJfIVmt4\n" +
            "K2rERzNJr5wlQ2fS3OVLM1dE1rs9WKvNgKwyB2vxmo0XIibqBnOks+1wxjKfoBiq\n" +
            "y4ZgbjMGgudmoj7v3ajvMPQuYhb616THUdq2kJcBjLZ489yBMgH7x5qmpPT/dS2e\n" +
            "tkwghX+Zui+/9jXsGLvof/btnsBou7CC0G/4RyeeoP52T3qmgf+aDv20asD2H1up\n" +
            "pQsVvsFHwELOrTZZVPJOfsJzp8bzjhNThGKDHXhL39IOYrFdZ8meZgml464IgAvA\n" +
            "2CFDM6qR6vxUPRF5LxEsC2Z/STXOIAqS6Gz91vcyOOm7MhloTdtuatIQVnknLNou\n" +
            "qz/KbE4k5pwkrh7jDKs+02ncFBQE+48LIngn2kxOvSMrWfUqqBVMPN8EZwc3fiav\n" +
            "lo5jnM/DXerMFKaoWht3OwF6g8Fxm9hFC9NbwKu8AvIB2c0GPk02OcnKjO2ddkGX\n" +
            "B9igrNWnxsl2XaZzEZyZptHb7W1JGAiX/EyzpZIcy0+kLY6bqyqz/OdsQfrkTNvZ\n" +
            "JH5kx06ehKLl+HzOLma1f8T+NbN27TkrfJSx3GqwYTXqoIBn+mphUE826hyoVzHL\n" +
            "sErDTACjKlOWG35INpF+qyUKs9mfO0c8u/qF2x8WMz5J+8j44Ee6So8qzjLbBbN+\n" +
            "km8ifjiODyP9cNe9yagJDnFrnDtzdZPrtjk1vghAY95ErZ7OdvQhRSu4mdRBZ552\n" +
            "DZM1Xb6UcJU/zl3xlPxGRXo3Lxv6sZtWDOLGhBT26kyU3qLp3KftoV6pNyqO4/a4\n" +
            "qfTqcBCz54bGx23y2VmMwgt69waAN3pDd34Ouqm6mV84//llN90aUPsolbrLwMD5\n" +
            "GyYaq6ytBBFO9/g7yX5CDJs1kX8k+qVBHhWdt3AmO+ghAQlsGguGTfm2tAcPx78F\n" +
            "toNXscFXs9BKHwNDWgdlkPdVr7b/PUNYDffnsTeTm4OC15g4G8RUEb6NyL4T0Ep4\n" +
            "/3iujmdnFhZ1w9LjFj7QN88kaK9JxadPv0F6C4Ht5ay67vXryxvJJ+NYRpw=\n" +
            "-----END ENCRYPTED PRIVATE KEY-----\n"

    const val PASSWORD = "supersecret"
}